# PowerShell---TSM-Backup-Script

A PowerShell module designed to process 1 or multiple workstation names to analyze Tivoli Storage Manager output files and generate  an error and remediation report.

Designed to save time by automaing the process of investigating why TSM backups failed on multiple workstations (especially in a corporate environment which maintains many workstations).

Use: Determine why workstations using the TSM Backup Service missed or failed a backup.

Process:
1. Run by passing a single workstation name (i.e. WW7WP972SSS003) or multiple workstation names via a .txt or spreadsheet file (using get-Content).

2. Reads the TSM Service values, TSM Error.log, TSM Sched.Log, and TSM OptFile.

3. Based on the content of these files and a set of criteria for numerous potential errors, the module returns errors and possible remediation steps for each workstation.
