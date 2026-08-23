# CSV authoritative source

CSV is the MVP authoritative people source. The flow is upload, streamed parse, preview, validation, change summary, explicit confirmation and apply. Defaults expect `employee_id`, `display_name`, `email`, `department`, `manager_id`, and `status`; mappings are administrative and limited to known person attributes.

Parsing uses byte and row limits, UTF-8 expectations, field validation and per-row errors. Apply uses organization, authoritative source and external person ID as the logical key, so re-import updates rather than duplicates people. CSV is untrusted input; exports prefix formula-leading cells to mitigate spreadsheet execution.
