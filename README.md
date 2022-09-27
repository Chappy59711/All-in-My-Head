# All-in-My-Head
Ideas - Most bad, some good

This ia a repository of tools I have developed over the years.  Some work really well, others are still a work in progress.  More information about each will be added over the next several days.

Attack Surface Analyzer - Must be run under an adminitrative account.  Graphical user interface that shows the configuration of the local machine vs a pre-determined configuation. This application is not completed.

Configuration Review

BL_VA_Daily gathers configuration information from a machine and write it to a file.  This was used in support of CIP compliance.

ConfigCheck shows the configuration of the local machine vs a pre-determined configuation.  The pre-configuration is contained in test.csv.

Discovery

BabyPingSweep - A simple ping sweep script.

New-p - Used on the Hak5 Bash Bunny and must be run under an administrative account.  Allows discovery to run from the connected system using local IP resouces such as ARP table, route table, DNS cache, and trace route.  Uses Disc_IP and SpiderNet scripts.

SpiderNet - Must be run under an administrative account.  Runs discovery from the system using local IP resouces such as ARP table, route table, DNS cache, and trace route.

Sweeper - Performs either a ping sweep and/or DNS resolution across an IP space.

Interrogation

Disc_IP - Must be run under an administrative account.  Performs a simple port scan with some telnet based interrogation of certain ports.  Also performs DNS resolution and IP location information from IPINFO.io.

Windows Firewall Analyzer - PowerShell
Windows Firewall Monitor - C
Windows Firewall Monitor - Python

Generic Security Strategy - Example of a Security Strategy document

Generic Vulnerability Assessment Report - Example of a Vulnerability Assessment document

WinFWMon.exe - C version of the Windows Firewall Monitor.
