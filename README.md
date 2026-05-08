Youtube Demo of Project: https://youtu.be/K2eARb8gZQk

## Overview of Project:
The Windows Security Assessment Tool follows a client-database architecture. The client application runs entirely on the Windows machine being audited. At startup it opens a connection to a MariaDB database hosted on a separate SQL server, retrieves the complete set of expected checks, performs all comparisons locally using Windows APIs and system libraries then renders the results in a graphical interface. The database connection is closed before the GUI is displayed. No scan data is transmitted to the server at any point.

## How to use:
This program can be run safely on any computer in demonstration. The only requirement being that the user must install a MariaDB database server and import the `db.sql` script via HeidiSQL or similar, the port `3306` and connection details are unchanged of their default of `root` for username and an empty field for password.

The SQL server must run local on the computer you wish to use the Windows Security Assessment Tool with, this is due to uncertainty that there will be a reliable internet connection during the Computing Expo.

## Poster:
<img width="2245" height="3179" alt="Windows System Compliance Checker3" src="https://github.com/user-attachments/assets/cf0b80c5-a2dc-4e6e-8386-2b16656a64ed" />
