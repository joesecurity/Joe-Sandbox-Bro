@load base/frameworks/files
@load base/files/extract
@load base/files/hash
@load base/protocols/http

module JoeSandbox;

export {
    #######################
    #     Settings        #
    #######################

    # Joe Sandbox api key
    const apikey: string = "YOUR_API_KEY" &redef;

    # Joe Sandbox api url
    # const apiurl: string = "http://example.net/joesandbox/index.php/api/";
    const apiurl: string = "https://jbxcloud.joesecurity.org/api/" &redef;

    # Please accept the Joe Sandbox Cloud Terms and Conditions if you are
    # using Joe Sandbox Cloud.
    # https://jbxcloud.joesecurity.org/download/termsandconditions.pdf
    const accept_tac: bool = F &redef;

    # timeout for uploading samples
    const submission_timeout: interval = 30sec &redef;

    # function to decide whether to analyze a sample or not
    const should_analyze = function(meta: fa_metadata): bool
        {
            const mime_types: set[string] = {
                "application/x-dosexec",
                "text/x-msdos-batch",
                # "application/x-mach-o-executable",
            };

            # There are too many undetected mime types out there for us to all
            # analyze them. Most of them are boring anyway.
            if (!meta?$mime_type) return F;

            return meta$mime_type in mime_types;
        } &redef;

    # Duration until we re-analyse an already analyzed sample.
    const cache_duration: interval = 365 days &redef;
}

export {
    type submission_id: string;

    type Submission: record {
        # Indicate whether the submission was sucessful or not.
        success: bool;

        # The submission id if success=T
        id: submission_id             &optional;
    };

    type Info: record {
        ## Time the sample was seen.
        ts: time                      &log;
        ## File id
        id: string                    &log;
        ## File path of the extracted sample.
        path: string;
        ## Boolean whether the sample was submitted to Joe Sandbox or not.
        submitted: bool               &log &default=F;
        ## Original filename of the sample if available.
        filename: string              &log &optional;
        ## Source of the sample. (HTTP, SMB, etc.)
        source: string                &log &optional;
        ## Details about the source such as the URI
        source_details: string        &log &optional;
        ## The Joe Sandbox submission_id for the sample.
        submission_id: submission_id  &log &optional;
    };

    redef enum Log::ID += { LOG };

    # forward declarations
    global submit: function(path: string): Submission;
}

# forward declarations
global remove_file: function(path: string);
global extract_submission: function(text: vector of string): Submission;

# cache for analyzed examples
global submitted_samples: table[string] of submission_id
    &synchronized
    &persistent
    &read_expire = cache_duration;

redef record fa_file += {
    # By convention, the name of this new field is the lowercase name
    # of the module.
    joesandbox: JoeSandbox::Info &optional;
};
    
# attach file extractor to files of interest
event file_sniff(f: fa_file, meta: fa_metadata) &priority=10
    {
        if (!should_analyze(meta)) return;

        local extract_filename = cat(Exec::tmp_dir, "/j-", f$id);

        # create attribute so we know in file_state_remove that we are interested
        # in this file
        f$joesandbox = [$id = f$id, $path = extract_filename, $ts = f$info$ts];

        # attach file extractor
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename = extract_filename]);
        Files::add_analyzer(f, Files::ANALYZER_SHA256);
    }

    
# upload extracted files to Joe Sandbox
event file_state_remove(f: fa_file)
    {
        if (!f?$joesandbox) return;

        # abort if the file was not completely captured
        if (f$missing_bytes != 0 && f$overflow_bytes != 0) {
            remove_file(f$joesandbox$path);
        }

        # add additional data to log
        if (f$info?$filename) {
            f$joesandbox$filename = f$info$filename;
        } else if (f?$http && f$http?$uri) {
            local match = match_pattern(f$http$uri, /[^\/]+$/);
            if (match$matched) {
                f$joesandbox$filename = match$str;
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
                f$joesandbox$submission_id = submitted_samples[f$info$sha256];
                Log::write(JoeSandbox::LOG, f$joesandbox);
                remove_file(f$joesandbox$path);
                return;
            }
        }

        # submit sample
        when (local submission = submit(f$joesandbox$path)) {
            remove_file(f$joesandbox$path);

            if (submission$success) {
                f$joesandbox$submitted = T;
                f$joesandbox$submission_id = submission$id;

                # remember sample
                if (f$info?$sha256) {
                    submitted_samples[f$info$sha256] = submission$id;
                }
            }

            Log::write(JoeSandbox::LOG, f$joesandbox);
        } timeout submission_timeout {
            remove_file(f$joesandbox$path);
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
    local cmd = fmt("rm \"%s\"", str_shell_escape(path));

    when (local result = Exec::run([$cmd=cmd])) {
        # do nothing
    } timeout 5sec {
        # do nothing
    }
}

#
# Extract the submission from the output of jbxapi.py
#
function extract_submission(text: vector of string): Submission
    {
        # Sample output
        # {
        #     "submission_id": "12345"
        # }

        for (i in text) {
            if (/"submission_id"/ !in text[i]) {
                next;
            }

            local secondPart = find_last(text[i], /:.*/);
            local withQuotes = find_last(secondPart, /\".*\"/);
            local id = sub_bytes(withQuotes, 2, |withQuotes| - 2);

            return Submission($success = T, $id = id);
        }

        # no submission_id found
        return Submission($success = F);
    }

#
# Submit a file to Joe Sandbox. (Needs to run asynchronously inside when().)
#
# Return the submission_id or ""
#
function submit(path: string): Submission
    {
        # run command
        local cmd = fmt("/usr/bin/env python -m jbxapi submit \"%s\" --apiurl \"%s\" --apikey \"%s\" --comments \"%s\" \"%s\"",
            accept_tac ? "--accept-tac" : "",
            str_shell_escape(apiurl),
            str_shell_escape(apikey),
            str_shell_escape("submitted by bro"),
            str_shell_escape(path)
        );
        local result = Exec::run([$cmd=cmd]);

        # parse result
        local submission = Submission($success = F);
        if (result?$exit_code && result$exit_code == 0 && result?$stdout) {
            submission = extract_submission(result$stdout);
        }

        # upon error report the output of jbxapi
        if (!submission$success) {
            # report the output of jbxapi.py
            if (result?$stdout) {
                for (i in result$stdout) {
                    Reporter::error(result$stdout[i]);
                }
            }

            if (result?$stderr) {
                for (i in result$stderr) {
                    Reporter::error(result$stderr[i]);
                }
            }
        }

        return submission;
    }
