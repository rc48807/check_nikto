# check_nikto
Vulnerability monitoring.

Web A vulnerability is a defect that can be exploited by an attacker aiming to subvert security policy, and may exist for several reasons, i.e. when certain parts originating from the request to the server, are processed without due treatment by the server, such as poorly configured cookies, session ID exposed in the browser, parameters passed by the URL or in a login form , featuring a security flaw, exposing the server to specific attacks.

This Nagios plugin monitors a domain in search of web vulnerabilities, so it uses the scan of Web Nikto vulnerabilities, producing an HTML report, and alerting to the existence of known vulnerabilities, returning the critical state in case of detection.
The domain to be monitored is passed as an argument, and can optionally be specified the port of communication, the board where the report will be stored, the name, and the validity time of the report, as well as the types of vulnerabilities to be searched.
NB: The execution of this plugin is only possible with the installation of the scan of web vulnerabilities Nikto

Mandatory arguments: The following argument must be specified when the module is executed:

-H or --host used to specify the domain name to be scanned.

Optional arguments: The following arguments are optionally invoked, as required by the User:

-P or --path used to specify the board where the report is stored.

-p or --port used to specify the port.

-r or --report used to assign a name to the report.

-t or --time used to specify expiration time in the report days.

-T or --tuning used to specify the types of vulnerabilities to be searched for in the domain.

-V or --version used to query the module version.

-A or --author used to query the author's data.

Command-Line Execution Example:

./check_nikto.py -H https://github.com -p 443 -r nagios
