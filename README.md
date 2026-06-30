# Vulnventory

Vulnventory is a lightweight Python CLI for organising penetration testing findings, evidence, screenshots, notes, captions, and report-writing support files.

```text
raw screenshots / scan output / notes
  -> organised engagement folder
  -> linked evidence and captions
  -> missing-field checklist
  -> report writing brief
  -> exported figures and report package
  -> final report written manually in Word, RStudio, or another editor
```

The tool does not scan targets, discover findings, exploit systems, decide severity, or use AI. Findings are entered manually by the tester.

## Features

- Create a structured engagement workspace.
- Import screenshots, scans, configs, notes, and other evidence.
- Link evidence to finding IDs.
- Keep evidence metadata in local JSON files.
- Add and update manually identified findings.
- Add scope notes for later report writing.
- Save a screenshot inbox and import the newest screenshots without retyping the folder path.
- Update screenshot captions after import.
- Generate a missing-field checklist.
- Generate a per-finding Markdown brief.
- Generate a full report-writing brief.
- Export screenshots as clean report-ready figure files.
- Package a report-writing bundle with brief, figures, CSV inventory, and JSON indexes.
- Keep SHA256 hashes internally for tracking, without forcing them into the writing brief.
- Use only the Python standard library.
- Optionally use `rich` for cleaner terminal tables and status output.

## Requirements

- Python 3.10 or newer recommended.
- No third-party Python packages are required for the core tool.
- Optional: install `rich` for nicer terminal tables, colours, and status panels.

Install the optional terminal UI dependency:

```powershell
py -m pip install -r requirements.txt
```

If `rich` is not installed, the script automatically falls back to plain text output.

Windows examples use:

```powershell
py vulnventory.py ...
```

If `py` is not available:

```powershell
python vulnventory.py ...
```

macOS/Linux:

```bash
python3 vulnventory.py ...
```

## Commands

Current commands:

```text
init
set-scope
set-inbox
import
import-new
add-finding
caption-evidence
delete-evidence
delete-finding
list-findings
list-evidence
missing
draft
build-brief
build-report
export-figures
package-report
add-note
status
tree
```

`build-report` is kept only as a compatibility alias for `build-brief`.

## Quick Workflow

Create an engagement:

```powershell
py vulnventory.py init Example_Assessment
```

Add scope notes:

```powershell
py vulnventory.py set-scope Example_Assessment `
  --in-scope "192.0.2.10, web-app.example.test" `
  --out-of-scope "Third-party services, denial-of-service testing" `
  --rules "No destructive testing. Testing window 9am-5pm." `
  --objectives "Validate manually identified vulnerabilities and collect supporting evidence." `
  --tester "Security Tester"
```

For large scopes, do not paste every IP address, hostname, or rule into the command line. Put the full scope files in `00_scope/` and use `set-scope` only for a short summary or a pointer to those files.

Save your normal screenshot folder once:

```powershell
py vulnventory.py set-inbox Example_Assessment `
  --screenshots "C:\Path\To\Screenshots"
```

Add a finding:

```powershell
py vulnventory.py add-finding Example_Assessment `
  --id F-001 `
  --title "Anonymous LDAP bind enabled" `
  --severity Medium `
  --affected "directory-server.example.test" `
  --summary "The domain controller allowed anonymous LDAP bind." `
  --impact "An unauthenticated user may enumerate directory information." `
  --likelihood "Exploitation is straightforward where LDAP is reachable." `
  --recommendation "Disable anonymous LDAP bind and restrict LDAP access."
```

Take screenshots normally, then import the newest screenshot from the saved inbox:

```powershell
py vulnventory.py import-new Example_Assessment `
  --finding F-001 `
  --host directory-server.example.test
```

Import the newest three screenshots:

```powershell
py vulnventory.py import-new Example_Assessment `
  --finding F-001 `
  --host directory-server.example.test `
  --count 3
```

You can still import a specific file, folder, or glob pattern manually:

```powershell
py vulnventory.py import Example_Assessment .\ldap_01_bind.png `
  --finding F-001 `
  --host directory-server.example.test `
  --type screenshot `
  --description "Anonymous LDAP bind result"
```

Review evidence:

```powershell
py vulnventory.py list-evidence Example_Assessment --finding F-001
```

Improve a caption:

```powershell
py vulnventory.py caption-evidence Example_Assessment E-0001 `
  --caption "LDAP query completed successfully without authentication"
```

Delete evidence from the index, but keep the copied evidence file on disk:

```powershell
py vulnventory.py delete-evidence Example_Assessment E-0001
```

Delete evidence from the index and remove the stored copy inside the engagement folder:

```powershell
py vulnventory.py delete-evidence Example_Assessment E-0001 --delete-file
```

Delete a finding that has no linked evidence:

```powershell
py vulnventory.py delete-finding Example_Assessment F-001
```

If the finding still has linked evidence, either delete those evidence IDs first or explicitly delete the linked evidence with the finding:

```powershell
py vulnventory.py delete-finding Example_Assessment F-001 --delete-evidence
```

Check what is missing:

```powershell
py vulnventory.py missing Example_Assessment
```

Generate the writing brief:

```powershell
py vulnventory.py build-brief Example_Assessment
```

Export clean figure files:

```powershell
py vulnventory.py export-figures Example_Assessment
```

Create a complete report-writing package:

```powershell
py vulnventory.py package-report Example_Assessment --zip
```

## Engagement Structure

`init` creates:

```text
Example_Assessment/
  00_scope/
  01_recon/
  02_scans/
  03_evidence/
  04_notes/
  05_findings/
  06_report/
  99_archive/
  .evidence_manager/
    evidence_index.json
    findings.json
    engagement.json
```

## Handling Large Scopes

For a small engagement, `set-scope` can store the important scope notes directly:

```powershell
py vulnventory.py set-scope Example_Assessment `
  --in-scope "192.0.2.10, web-app.example.test" `
  --out-of-scope "DoS testing, third-party systems" `
  --rules "No destructive testing"
```

For a large engagement, treat `00_scope/` as the source of truth. Store the real scope documents there:

```text
00_scope/
  scope_summary.md
  asset_list.csv
  ip_ranges.txt
  excluded_assets.txt
  rules_of_engagement.pdf
  authorization_email.pdf
```

Then use `set-scope` to point to those files:

```powershell
py vulnventory.py set-scope Example_Assessment `
  --in-scope "See 00_scope/asset_list.csv and 00_scope/ip_ranges.txt" `
  --out-of-scope "See 00_scope/excluded_assets.txt" `
  --rules "No DoS. See 00_scope/rules_of_engagement.pdf" `
  --objectives "See 00_scope/scope_summary.md" `
  --tester "Security Tester"
```

This keeps the command short while preserving the full scope record inside the engagement folder. The generated brief will include the short scope summary and file references, while the detailed documents remain available in `00_scope/`.

## Core Files

```text
.evidence_manager/findings.json
.evidence_manager/evidence_index.json
.evidence_manager/engagement.json
```

These are the local source of truth. They store finding text, evidence metadata, scope notes, internal status, SHA256 hashes, timestamps, and file locations.

## Screenshot Inbox Workflow

The screenshot inbox workflow avoids copying screenshots into the project root and avoids typing the absolute screenshot folder path every time.

Set the inbox once:

```powershell
py vulnventory.py set-inbox Example_Assessment `
  --screenshots "C:\Path\To\Screenshots"
```

Then import the newest screenshot:

```powershell
py vulnventory.py import-new Example_Assessment `
  --finding F-001 `
  --host web-app.example.test
```

Import the newest three screenshots:

```powershell
py vulnventory.py import-new Example_Assessment `
  --finding F-001 `
  --host web-app.example.test `
  --count 3
```

`--count` means how many of the newest screenshots to import from the inbox. For example, `--count 3` imports the three most recently modified screenshot files.

By default, `import-new` skips screenshot files that were already imported from the inbox. This helps prevent accidental duplicate evidence.

If needed, allow re-importing already imported files:

```powershell
py vulnventory.py import-new Example_Assessment `
  --finding F-001 `
  --host web-app.example.test `
  --count 1 `
  --include-imported
```

Only import screenshots taken recently:

```powershell
py vulnventory.py import-new Example_Assessment `
  --finding F-001 `
  --host web-app.example.test `
  --count 5 `
  --since-minutes 20
```

Use a different screenshot folder for one import without changing the saved inbox:

```powershell
py vulnventory.py import-new Example_Assessment `
  --finding F-001 `
  --host web-app.example.test `
  --count 2 `
  --path "D:\Path\To\Screenshots"
```

Supported screenshot extensions:

```text
.png
.jpg
.jpeg
.bmp
.gif
.webp
```

## Evidence Types

Valid `--type` values:

```text
screenshot
scan
note
exploit-output
config
credential-evidence
other
```

Evidence locations:

```text
scan        -> 02_scans/<finding_id>/<host>/
note        -> 04_notes/<finding_id>/<host>/
everything else -> 03_evidence/<finding_id>/<host>/
```

## Finding Fields

Required when adding a finding:

```text
--id
--title
--severity
--affected
```

Recommended for a ready finding:

```text
--summary
--impact
--likelihood
--recommendation
```

Valid severities:

```text
Critical
High
Medium
Low
Informational
```

## Missing Checklist

Use this before writing the final report:

```powershell
py vulnventory.py missing Example_Assessment
```

Example:

```text
F-001 - Anonymous LDAP bind enabled
  Ready for report writing: no
  Evidence items: 2
  Screenshots: 1
  Missing fields: likelihood, recommendation
```

## Report Brief

Generate:

```powershell
py vulnventory.py build-brief Example_Assessment
```

Output:

```text
06_report/report_brief.md
```

The brief includes:

- scope notes
- missing checklist
- findings summary
- each finding's manually entered text
- related evidence table
- evidence file references
- figure labels
- screenshot image links
- extracted text summaries
- evidence inventory

This is a writing pack, not a final report.

## Figure Export

Generate clean report-ready image names:

```powershell
py vulnventory.py export-figures Example_Assessment
```

Output:

```text
06_report/figures/
  Figure_01_F-001_E-0001_Anonymous_LDAP_bind_result.png
  Figure_02_F-001_E-0002_LDAP_query_output.png
```

Export only one finding:

```powershell
py vulnventory.py export-figures Example_Assessment --finding F-001
```

## Report Package

Create a full writing bundle:

```powershell
py vulnventory.py package-report Example_Assessment --zip
```

Output:

```text
06_report/report_package/
  report_brief.md
  evidence_inventory.csv
  findings.json
  evidence_index.json
  figures/

06_report/report_package.zip
```

This is the most useful output when you want to write the final report in Word or RStudio.

## Notes

Create a note and import it as evidence:

```powershell
py vulnventory.py add-note Example_Assessment `
  --title "LDAP testing note" `
  --body "Anonymous bind was observed during enumeration." `
  --finding F-001 `
  --host directory-server.example.test
```

## Status And Tree

```powershell
py vulnventory.py status Example_Assessment
```

```powershell
py vulnventory.py tree Example_Assessment
```

## Suggested Direction

Use this project as an evidence organiser and writing assistant:

```text
collect -> organise -> caption -> check missing -> export figures -> package -> write report manually
```

Avoid using it as a final report generator. Final report writing still needs judgement, context, and narrative flow.

## License

MIT License. 

