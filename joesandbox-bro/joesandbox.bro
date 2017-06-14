@load base/frameworks/files
@load base/files/extract
@load base/files/hash
@load base/protocols/http

module JoeSandbox;

type FilterMode: enum { Inclusion, Exclusion };

export {
    #######################
    #     Settings        #
    #######################

    # path to the jbxapi.py script
    const jbxapi_script: string = "./jbxapi.py" &redef;

    # path to the extract_files directory of bro
    const extract_files_dir: string = "extract_files" &redef;

    # timeout for uploading samples
    const submission_timeout: interval = 30sec &redef;
    
    # By default, this script uses a short inclusion list with
    # only executables selected.
    # You can choose to upload all files filtered by an
    # exclusion list.
    const mode: FilterMode = Inclusion;
    #const mode: FilterMode = Exclusion;

    const inclusion_list: set[string] {
        "application/x-dosexec",
        "text/x-msdos-batch",
        # "application/x-mach-o-executable",
    } &redef;
    
    # List of mime types to exclude in the ExclusionList mode.
    # https://github.com/bro/bro/tree/master/scripts/base/frameworks/files/magic
    const exclusion_list_patterns: vector of pattern = {
        /image\/.*/,
        /video\/.*/,
        /audio\/.*/,
        /application\/(x-)?font-.*/,
        /text\/.*/,     # python, ruby, etc. scripts are also included here
    } &redef;

    const exclusion_list_strings: set[string] = {
        # macOS specific
        "application/x-mach-o-executable",
        "application/x-dmg",
        "application/x-xar",

        # others
        "application/ocsp-response",
        "application/ocsp-request",
        "application/pkix-cert",
    } &redef;

    type webid: count;

    type Info: record {
        ts: time                &log;           # time the file was seen
        filename: string        &log;
        submitted: bool         &log &default=F;
        orig_filename: string   &log &optional;
        source: string          &log &optional;
        source_details: string  &log &optional;
        webids: set[webid]      &log &optional;
    };

    redef enum Log::ID += { LOG };
}

# forward declarations
global remove_file: function(path: string);
global extract_webids: function(text: vector of string): set[webid];
global submit: function(path: string): set[webid];

# cache for analyzed examples
global submitted_samples: table[string] of set[webid]
    &synchronized
    &persistent
    &read_expire = 30 days
    &write_expire = 365 days;

redef record fa_file += {
    # By convention, the name of this new field is the lowercase name
    # of the module.
    joesandbox: JoeSandbox::Info &optional;
};
    
# attach file extractor to files of interest
event file_sniff(f: fa_file, meta: fa_metadata)
    {
        # There are too many undetected mime types out there for us to all
        # analyze them. Most of them are boring anyway.
        if (!meta?$mime_type) return;

        # determine if we are interested in this file
        if (mode == Inclusion) {
            if (meta$mime_type !in inclusion_list) {
                return;
            }
        } else {
            if (meta$mime_type in exclusion_list_strings) {
                return;
            }
            for (i in exclusion_list_patterns) {
                if (exclusion_list_patterns[i] == meta$mime_type) return;
            }
        }

        local filename = cat("j-bro-", f$id);
        # jbxapi.py only accepts lower case file paths
        filename = to_lower(filename);

        # create attribute so we know in file_state_remove that we are interested
        # in this file
        f$joesandbox = [$filename = filename, $ts = f$info$ts];

        # attach file extractor
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename = filename]);
        Files::add_analyzer(f, Files::ANALYZER_SHA256);
    }

    
# upload extracted files to Joe Sandbox
event file_state_remove(f: fa_file)
    {
        if (!f?$joesandbox) return;

        local path = fmt("%s/%s", extract_files_dir, f$joesandbox$filename);

        # abort if the file was not completely captured
        if (f$missing_bytes != 0 && f$overflow_bytes != 0) {
            remove_file(path);
        }

        # add additional data to log
        if (f$info?$filename) {
            f$joesandbox$orig_filename = f$info$filename;
        } else if (f?$http && f$http?$uri) {
            local match = match_pattern(f$http$uri, /[^\/]+$/);
            if (match$matched) {
                f$joesandbox$orig_filename = match$str;
            }
        }
        if (f$info?$source) {
            f$joesandbox$source = f$info$source;
        }
        if (f?$http) {
            if (f$http?$uri && f$http?$host) {
                f$joesandbox$source_details = f$http$host + f$http$uri;
            } else if (f$http?$uri) {
                f$joesandbox$source_details = f$http$uri;
            }
        }

        # log and early return if we have already analysed this file
        if (f$info?$sha256) {
            if (f$info$sha256 in submitted_samples) {
                f$joesandbox$webids = submitted_samples[f$info$sha256];
                Log::write(JoeSandbox::LOG, f$joesandbox);
                remove_file(path);
                return;
            }
        }

        # submit sample
        when (local webids = submit(path)) {
            remove_file(path);

            if (|webids| > 0) {
                f$joesandbox$submitted = T;
                f$joesandbox$webids = webids;

                Log::write(JoeSandbox::LOG, f$joesandbox);

                # remember sample
                if (f$info?$sha256) {
                    submitted_samples[f$info$sha256] = webids;
                }
            } else {
                print "Error uploading, no webid found.";
            }
        } timeout submission_timeout {
            remove_file(path);
        }
    }

event bro_init()
    {
        Log::create_stream(JoeSandbox::LOG, [$columns=JoeSandbox::Info, $path="joesandbox"]);
    }

#
# Remove the specified file.
#
function remove_file(path: string) {
    local cmd = fmt("rm %s", str_shell_escape(path));

    when (local result = Exec::run([$cmd=cmd])) {
        # do nothing
    } timeout 5sec {
        # do nothing
    }
}

#
# Extract webids from the output of jbxapi.py
# Returns an empty vecotr on error.
#
function extract_webids(text: vector of string): set[webid]
    {
        # Sample output
        # {
        #     "webid": 297802,
        #     "webids": [
        #         297802
        #     ]
        # }

        local webids: set[webid];

        # ensure we parse a valid response
        if (!(|text| >= 2 && "webid" in text[2])) {
            return webids;
        }

        local all_text = join_string_vec(text, "\n");

        # get all numbers in stdout
        local webid_strings = find_all(all_text, /[0-9]+/);
        for (webid_string in webid_strings) {
            add webids[to_count(webid_string)];
        }

        return webids;
    }

#
# Submit a file to Joe Sandbox. (Needs to run asynchronously inside when().)
#
# Returns the set of webids. (Empty on error.)
#
function submit(path: string): set[webid]
    {
        # run command
        local cmd = fmt("/usr/bin/env python %s analyze %s", jbxapi_script, str_shell_escape(path));
        local result = Exec::run([$cmd=cmd]);

        # parse result
        local webids: set[webid];

        if (result?$stdout) {
            webids = extract_webids(result$stdout);
        }

        # upon error print output of jbxapi
        if (|webids| == 0) {
            # print the output of jbxapi.py
            if (result?$stdout) {
                for (i in result$stdout) {
                    print result$stdout[i];
                }
            }

            if (result?$stderr) {
                for (i in result$stderr) {
                    print result$stderr[i];
                }
            }
           
        }

        return webids;
    }
