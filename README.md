Youtube Demo of Project: https://youtu.be/K2eARb8gZQk

## Overview of Project:
The Windows Security Assessment Tool follows a client-database architecture. The client application runs entirely on the Windows machine being audited. At startup it opens a connection to a MariaDB database hosted on a separate SQL server, retrieves the complete set of expected checks, performs all comparisons locally using Windows APIs and system libraries then renders the results in a graphical interface. The database connection is closed before the GUI is displayed. No scan data is transmitted to the server at any point.

## How to use:
This program can be safely run on any computer in demostration. The only requirement being that the user must install a MariaDB database server and import the `db.sql` script via HeidiSQL or similar, the port and connection details are unchanged of their default of `root` for username and an empty field for password.

The SQL server must run local on the computer you wish to use the Windows Security Assessment Tool with, this is due to uncertentity that there will be a realible internet connection during the Computing Expo.
