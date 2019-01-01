:page_template: fullwidth.html
:title: overview

.. raw:: html
     :file: overview.html


Features and Highlights
=======================

The following list is a summary of some of the most significant
features. As Velociraptor gains more features, this list will be
expanded.

* Find files on endpoints using glob expressions, file metadata and
  even Yara signatures.
* Search through registry using glob expressions, metadata and even
  Yara signatures.
* Apply Yara signatures to process memory.
* Acquire process memory based on various conditions for further
  examination by Windbg.
* Upload entire files from endpoints automatically and on demand.
* Raw NTFS parsing for access to locked files like the pagefile and
  registry hives.
* Full WMI support - Artifacts can express WMI queries and combine
  these with other queries (e.g. download files mentioned in the WMI
  results).
* Velociraptor supports streaming even queries - data can be collected
  automatically from endpoints and stored on the server. For example
  all these may be streamed to the server:

  - Process execution logs.
  - High value events parsed from the event logs.
  - DNS Queries and answers

* Escalations can be automatically actioned server side upon
  collection of client events..
* Interactive shell is available for those unexpected times when you
  need to get hands on!
* Advanced GUI making many tasks easy.
* Server side VQL allows for automating the server using VQL - launch
  further collection automatically when certain conditions are
  detected.
