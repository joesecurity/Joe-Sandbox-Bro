# JoeSandbox-Bro

JoeSandbox-[Bro](https://www.bro.org) is a simple bro script which extracts files from your internet connection and analyzes them automatically on [Joe Sandbox](https://www.joesecurity.org/).
By using this script you can fetch and detect malware payloads in HTTP, FTP and other protocols. Combined with Joe Sandbox's report and alerting features you can build with JoeSandbox-Bro a powerful IDS. 

![Bro extracts files between the internet and your hosts and uploads them to Joe Sandbox.](img/flow.png)

# Requirements

* Python 2
* Bro 2.4

# Installation

1. Copy joesandbox.bro and jbxapi.py onto your Bro machine.
2. Configure `jbxapi.py` with your API key and accept the terms and conditions.
3. Configure the paths at the top of `joesandbox.bro`. While you are testing the script, you can leave them in their default configuration.

Now you are ready to test the script. Run `bro`:

    sudo bro -C -i en1 joesandbox.bro
    
You can monitor the log file of the script:

    tail -f joesandbox.log

If the script is working properly, you should now setup an alert to get notificed if Joe Sandbox detect a file as malicious.
For this, open the alerts page in the web interface of Joe Sandbox and add a new alert. Set the `XPath` field to

    /analysis/signaturedetections/strategy[@name='empiric']/detection[text()='MAL']
    
Then add e-mail addresses and finally save the alert. You will now receive alerts for all malicious analysis.

# Example

During analysis in a network we were able to detect second stage downloads by [Kovter](www.joesecurity.org/reports/report-710857729c9adb7e41d9aac8ed842329.html):

![detected kovter samples](img/overview.png)

![e-mail alert for kovter](img/alert.png)

![kovter http](img/kovter.png)

# License

The code is licensed under MIT.

# Links

* [Bro](https://www.bro.org) 
* [Joe Sandbox Cloud](https://www.joesecurity.org/joe-sandbox-cloud)

# Author

Joe Security (@[joe4security](https://twitter.com/#!/joe4security) - [webpage](https://www.joesecurity.org))
