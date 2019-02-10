This page displays information about the Velociraptor built in
artifacts. There are 54 artifacts in total. Use the navigation menu
to the right to quickly skip to the right artifact
definition. Definitions may be expanded to view the VQL source.

.. |Admin_Client_UpgradeDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Admin_Client_UpgradeDetails" role="button"
     aria-expanded="false" aria-controls="Admin_Client_UpgradeDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Admin.Client.Upgrade
********************
|Admin_Client_UpgradeDetails| Remotely push new client updates.

NOTE: The updates can be pulled from any web server. You need to
ensure they are properly secured with SSL and at least a random
nonce in their path. You may configure the Velociraptor server to
serve these through the public directory.


.. raw:: html

  <div class="collapse" id="Admin_Client_UpgradeDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Admin.Client.Upgrade
   description: |
     Remotely push new client updates.
   
     NOTE: The updates can be pulled from any web server. You need to
     ensure they are properly secured with SSL and at least a random
     nonce in their path. You may configure the Velociraptor server to
     serve these through the public directory.
   
   parameters:
     - name: clientURL
       default: http://127.0.0.1:8000/public/velociraptor.exe
     - name: configURL
       default: http://127.0.0.1:8000/public/client.config.yaml
   
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           /* This query fetches the binary and config and stores them in
            temp files. Note that tempfiles will be automatically
            cleaned at query end.
            */
           LET tmpfiles <= SELECT tempfile(
              data=query(vql={
                SELECT Content
                FROM http_client(url=clientURL, chunk_size=30000000)
              }),
              extension=".exe") as Binary,
           tempfile(
              data=query(vql={
                SELECT Content
                FROM http_client(url=configURL)
              })) as Config from scope()
   
         - |
           // Run the installer.
           SELECT * from foreach(
            row=tmpfiles,
            query={
               SELECT * from execve(
                  argv=[Binary, "--config", Config, "-v", "service", "install"]
               )
            })

.. raw:: html

   </div></div>


.. |Admin_Events_PostProcessUploadsDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Admin_Events_PostProcessUploadsDetails" role="button"
     aria-expanded="false" aria-controls="Admin_Events_PostProcessUploadsDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Admin.Events.PostProcessUploads
*******************************
|Admin_Events_PostProcessUploadsDetails| Sometimes we would like to post process uploads collected as part of
the hunt's artifact collections

Post processing means to watch the hunt for completed flows and run
a post processing command on the files obtained from each host.

The command will receive the list of paths of the files uploaded by
the artifact. We dont actually care what the command does with those
files - we will just relay our stdout/stderr to the artifact's
result set.


.. raw:: html

  <div class="collapse" id="Admin_Events_PostProcessUploadsDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Admin.Events.PostProcessUploads
   description: |
     Sometimes we would like to post process uploads collected as part of
     the hunt's artifact collections
   
     Post processing means to watch the hunt for completed flows and run
     a post processing command on the files obtained from each host.
   
     The command will receive the list of paths of the files uploaded by
     the artifact. We dont actually care what the command does with those
     files - we will just relay our stdout/stderr to the artifact's
     result set.
   
   parameters:
     - name: uploadPostProcessCommand
       description: |
         The command to run - must be a json array of strings! The list
         of files will be appended to the end of the command.
       default: |
         ["/bin/ls", "-l"]
   
     - name: uploadPostProcessArtifact
       description: |
         The name of the artifact to watch.
       default: Windows.Registry.NTUser.Upload
   
   sources:
     - precondition:
         SELECT server_config FROM scope()
       queries:
         - |
           LET files = SELECT Flow,
               array(a1=parse_json_array(data=uploadPostProcessCommand),
                     a2=file_store(path=Flow.FlowContext.uploaded_files)) as Argv
           FROM watch_monitoring(artifact='System.Flow.Completion')
           WHERE uploadPostProcessArtifact in Flow.FlowContext.artifacts
   
         - |
           SELECT * from foreach(
             row=files,
             query={
                SELECT Flow.Urn as FlowUrn, Argv,
                       Stdout, Stderr, ReturnCode
                FROM execve(argv=Argv)
             })

.. raw:: html

   </div></div>


.. |Admin_System_CompressUploadsDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Admin_System_CompressUploadsDetails" role="button"
     aria-expanded="false" aria-controls="Admin_System_CompressUploadsDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Admin.System.CompressUploads
****************************
|Admin_System_CompressUploadsDetails| Compresses all uploaded files.

When artifacts collect files they are normally stored on the server
uncompressed. This artifact watches all completed flows and
compresses the files in the file store when the flow completes. This
is very useful for cloud based deployments with limited storage
space or when collecting large files.

In order to run this artifact you would normally run it as part of
an artifact acquisition process:

```
$ velociraptor --config /etc/server.config.yaml artifacts acquire Admin.System.CompressUploads
```

Note that there is nothing special about compressed files - you can
also just run `find` and `gzip` in the file store. Velociraptor will
automatically decompress the file when displaying it in the GUI
text/hexdump etc.


.. raw:: html

  <div class="collapse" id="Admin_System_CompressUploadsDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Admin.System.CompressUploads
   description: |
     Compresses all uploaded files.
   
     When artifacts collect files they are normally stored on the server
     uncompressed. This artifact watches all completed flows and
     compresses the files in the file store when the flow completes. This
     is very useful for cloud based deployments with limited storage
     space or when collecting large files.
   
     In order to run this artifact you would normally run it as part of
     an artifact acquisition process:
   
     ```
     $ velociraptor --config /etc/server.config.yaml artifacts acquire Admin.System.CompressUploads
     ```
   
     Note that there is nothing special about compressed files - you can
     also just run `find` and `gzip` in the file store. Velociraptor will
     automatically decompress the file when displaying it in the GUI
     text/hexdump etc.
   
   parameters:
     - name: blacklistCompressionFilename
       description: Filenames which match this regex will be excluded from compression.
       default: '(?i).+ntuser.dat'
   
   sources:
     - precondition:
         SELECT server_config FROM scope()
       queries:
         - |
           LET files = SELECT ClientId,
               Flow.Urn as Flow,
               Flow.FlowContext.uploaded_files as Files
           FROM watch_monitoring(artifact='System.Flow.Completion')
           WHERE Files and not Files =~ blacklistCompressionFilename
   
         - |
           SELECT ClientId, Flow, Files,
                  compress(path=Files) as CompressedFiles
           FROM files

.. raw:: html

   </div></div>


.. |Demo_Plugins_FifoDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Demo_Plugins_FifoDetails" role="button"
     aria-expanded="false" aria-controls="Demo_Plugins_FifoDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Demo.Plugins.Fifo
*****************
|Demo_Plugins_FifoDetails| This is a demo of the fifo() plugin. The Fifo plugin collects and
caches rows from its inner query. Every subsequent execution of the
query then reads from the cache. The plugin will expire old rows
depending on its expiration policy - so we always see recent rows.

You can use this to build queries which consider historical events
together with current events at the same time. In this example, we
check for a successful logon preceeded by a number of failed logon
attempts.

In this example, we use the clock() plugin to simulate events. We
simulate failed logon attempts using the clock() plugin every
second. By feeding the failed logon events to the fifo() plugin we
ensure the fifo() plugin cache contains the last 5 failed logon
events.

We simulate a successful logon event every 3 seconds, again using
the clock plugin. Once a successful logon event is detected, we go
back over the last 5 login events, count them and collect the last
failed logon times (using the GROUP BY operator we group the
FailedTime for every unique SuccessTime).

If we receive more than 3 events, we emit the row.

This now represents a high value signal! It will only occur when a
successful logon event is preceeded by at least 3 failed logon
events in the last hour. It is now possible to escalate this on the
server via email or other alerts.

Here is sample output:

.. code-block:: json

    {
      "Count": 5,
      "FailedTime": [
        1549527272,
        1549527273,
        1549527274,
        1549527275,
        1549527276
      ],
      "SuccessTime": 1549527277
    }

Of course in the real artifact we would want to include more
information than just times (i.e. who logged on to where etc).


.. raw:: html

  <div class="collapse" id="Demo_Plugins_FifoDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Demo.Plugins.Fifo
   description: |
     This is a demo of the fifo() plugin. The Fifo plugin collects and
     caches rows from its inner query. Every subsequent execution of the
     query then reads from the cache. The plugin will expire old rows
     depending on its expiration policy - so we always see recent rows.
   
     You can use this to build queries which consider historical events
     together with current events at the same time. In this example, we
     check for a successful logon preceeded by a number of failed logon
     attempts.
   
     In this example, we use the clock() plugin to simulate events. We
     simulate failed logon attempts using the clock() plugin every
     second. By feeding the failed logon events to the fifo() plugin we
     ensure the fifo() plugin cache contains the last 5 failed logon
     events.
   
     We simulate a successful logon event every 3 seconds, again using
     the clock plugin. Once a successful logon event is detected, we go
     back over the last 5 login events, count them and collect the last
     failed logon times (using the GROUP BY operator we group the
     FailedTime for every unique SuccessTime).
   
     If we receive more than 3 events, we emit the row.
   
     This now represents a high value signal! It will only occur when a
     successful logon event is preceeded by at least 3 failed logon
     events in the last hour. It is now possible to escalate this on the
     server via email or other alerts.
   
     Here is sample output:
   
     .. code-block:: json
   
         {
           "Count": 5,
           "FailedTime": [
             1549527272,
             1549527273,
             1549527274,
             1549527275,
             1549527276
           ],
           "SuccessTime": 1549527277
         }
   
     Of course in the real artifact we would want to include more
     information than just times (i.e. who logged on to where etc).
   
   sources:
     - queries:
         # This query simulates failed logon attempts.
         - LET failed_logon = SELECT Unix as FailedTime from clock(period=1)
   
         # This is the fifo which holds the last 5 failed logon attempts
         # within the last hour.
         - LET last_5_events = SELECT FailedTime
               FROM fifo(query=failed_logon, max_rows=5, max_age=3600)
   
         # We need to get it started collecting data immediately by
         # materializing the cache contents. Otherwise the fifo wont
         # start until it is first called (i.e. the first successful
         # login and we will miss the failed events before hand).
         - LET foo <= SELECT * FROM last_5_events
   
         # This simulates successful logon - we assume every 3 seonds.
         - LET success_logon = SELECT Unix as SuccessTime from clock(period=3)
   
         # For each successful logon, query the last failed logon
         # attempts from the fifo(). We also count the total number of
         # failed logons. We only actually emit results if there are more
         # than 3 failed logon attempts before each successful one.
         - |
           SELECT * FROM foreach(
             row=success_logon,
             query={
              SELECT SuccessTime, FailedTime, count(items=FailedTime) as Count
              FROM last_5_events GROUP BY SuccessTime
             }) WHERE Count > 3

.. raw:: html

   </div></div>


.. |Generic_Client_StatsDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Generic_Client_StatsDetails" role="button"
     aria-expanded="false" aria-controls="Generic_Client_StatsDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Generic.Client.Stats
********************
|Generic_Client_StatsDetails| An Event artifact which generates client's CPU and memory statistics.

.. raw:: html

  <div class="collapse" id="Generic_Client_StatsDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Generic.Client.Stats
   description: An Event artifact which generates client's CPU and memory statistics.
   parameters:
     - name: Frequency
       description: Return stats every this many seconds.
       default: "10"
   
   sources:
     - queries:
         - |
           SELECT * from foreach(
            row={
              SELECT UnixNano FROM clock(period=atoi(string=Frequency))
            },
            query={
              SELECT UnixNano / 1000000000 as Timestamp,
                     Times.user + Times.system as CPU,
                     MemoryInfo.RSS as RSS
              FROM pslist(pid=getpid())
            })

.. raw:: html

   </div></div>


.. |Linux_Applications_Chrome_ExtensionsDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Linux_Applications_Chrome_ExtensionsDetails" role="button"
     aria-expanded="false" aria-controls="Linux_Applications_Chrome_ExtensionsDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Linux.Applications.Chrome.Extensions
************************************
|Linux_Applications_Chrome_ExtensionsDetails| Fetch Chrome extensions.

Chrome extensions are installed into the user's home directory.  We
search for manifest.json files in a known path within each system
user's home directory. We then parse the manifest file as JSON.

Many extensions use locale packs to resolve strings like name and
description. In this case we detect the default locale and load
those locale files. We then resolve the extension's name and
description from there.


.. raw:: html

  <div class="collapse" id="Linux_Applications_Chrome_ExtensionsDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Linux.Applications.Chrome.Extensions
   description: |
     Fetch Chrome extensions.
   
     Chrome extensions are installed into the user's home directory.  We
     search for manifest.json files in a known path within each system
     user's home directory. We then parse the manifest file as JSON.
   
     Many extensions use locale packs to resolve strings like name and
     description. In this case we detect the default locale and load
     those locale files. We then resolve the extension's name and
     description from there.
   
   parameters:
     - name: extensionGlobs
       default: /.config/google-chrome/*/Extensions/*/*/manifest.json
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'linux'
       queries:
         - |
           /* For each user on the system, search for extension manifests
              in their home directory. */
           LET extension_manifests = SELECT * from foreach(
             row={
                SELECT Uid, User, Homedir from Artifact.Linux.Sys.Users()
             },
             query={
                SELECT FullPath, Mtime, Ctime, User, Uid from glob(
                  globs=Homedir + '/' + extensionGlobs)
             })
   
         - |
           /* If the Manifest declares a default_locale then we
              load and parse the messages file. In this case the
              messages are actually stored in the locale file
              instead of the main manifest.json file.
           */
           LET maybe_read_locale_file =
              SELECT * from if(
                 condition={
                    select * from scope() where Manifest.default_locale
                 },
                 then={
                    SELECT Manifest,
                           Uid, User,
                           Filename as LocaleFilename,
                           ManifestFilename,
                           parse_json(data=Data) AS LocaleManifest
                    FROM read_file(
                            -- Munge the filename to get the messages.json path.
                            filenames=regex_replace(
                              source=ManifestFilename,
                              replace="/_locales/" + Manifest.default_locale +
                                      "/messages.json",
                              re="/manifest.json$"))
                 },
                 else={
                     -- Just fill in empty Locale results.
                     SELECT Manifest,
                            Uid, User,
                            "" AS LocaleFilename,
                            "" AS ManifestFilename,
                            "" AS LocaleManifest
                     FROM scope()
                 })
   
         - |
           LET parse_json_files = SELECT * from foreach(
              row={
                SELECT Filename as ManifestFilename,
                       Uid, User,
                       parse_json(data=Data) as Manifest
                FROM read_file(filenames=FullPath)
              },
              query=maybe_read_locale_file)
   
         - |
           LET parsed_manifest_files = SELECT * from foreach(
             row=extension_manifests,
             query=parse_json_files)
   
         - |
           SELECT Uid, User,
   
                  /* If the manifest name contains __MSG_ then the real
                     name is stored in the locale manifest. This condition
                     resolves the Name column either to the main manifest or
                     the locale manifest.
                  */
                  if(condition="__MSG_" in Manifest.name,
                     then=get(item=LocaleManifest,
                        member=regex_replace(
                           source=Manifest.name,
                           replace="$1",
                           re="(?:__MSG_(.+)__)")).message,
                     else=Manifest.name) as Name,
   
                  if(condition="__MSG_" in Manifest.description,
                     then=get(item=LocaleManifest,
                        member=regex_replace(
                           source=Manifest.description,
                           replace="$1",
                           re="(?:__MSG_(.+)__)")).message,
                     else=Manifest.description) as Description,
   
                  /* Get the Identifier and Version from the manifest filename */
                  regex_replace(
                    source=ManifestFilename,
                    replace="$1",
                    re="(?:.+Extensions/([^/]+)/([^/]+)/manifest.json)$") AS Identifier,
                  regex_replace(
                    source=ManifestFilename,
                    replace="$2",
                    re="(?:.+Extensions/([^/]+)/([^/]+)/manifest.json)$") AS Version,
   
                  Manifest.author as Author,
                  Manifest.background.persistent AS Persistent,
                  regex_replace(
                    source=ManifestFilename,
                    replace="$1",
                    re="(.+Extensions/.+/)manifest.json$") AS Path,
   
                  Manifest.oauth2.scopes as Scopes,
                  Manifest.permissions as Permissions,
                  Manifest.key as Key
   
           FROM parsed_manifest_files

.. raw:: html

   </div></div>


.. |Linux_Applications_Chrome_Extensions_UploadDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Linux_Applications_Chrome_Extensions_UploadDetails" role="button"
     aria-expanded="false" aria-controls="Linux_Applications_Chrome_Extensions_UploadDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Linux.Applications.Chrome.Extensions.Upload
*******************************************
|Linux_Applications_Chrome_Extensions_UploadDetails| Upload all users chrome extension.

We dont bother actually parsing anything here, we just grab all the
extension files in user's home directory.


.. raw:: html

  <div class="collapse" id="Linux_Applications_Chrome_Extensions_UploadDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Linux.Applications.Chrome.Extensions.Upload
   description: |
     Upload all users chrome extension.
   
     We dont bother actually parsing anything here, we just grab all the
     extension files in user's home directory.
   
   parameters:
     - name: extensionGlobs
       default: /.config/google-chrome/*/Extensions/**
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'linux'
       queries:
         - |
           /* For each user on the system, search for extension files
              in their home directory and upload them. */
           SELECT * from foreach(
             row={
                SELECT Uid, User, Homedir from Artifact.Linux.Sys.Users()
             },
             query={
                SELECT FullPath, Mtime, Ctime, User, Uid,
                       upload(file=FullPath) as Upload
                FROM glob(globs=Homedir + '/' + extensionGlobs)
             })

.. raw:: html

   </div></div>


.. |Linux_Applications_Docker_InfoDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Linux_Applications_Docker_InfoDetails" role="button"
     aria-expanded="false" aria-controls="Linux_Applications_Docker_InfoDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Linux.Applications.Docker.Info
******************************
|Linux_Applications_Docker_InfoDetails| Get Dockers info by connecting to its socket.

.. raw:: html

  <div class="collapse" id="Linux_Applications_Docker_InfoDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Linux.Applications.Docker.Info
   description: Get Dockers info by connecting to its socket.
   parameters:
     - name: dockerSocket
       description: |
         Docker server socket. You will normally need to be root to connect.
       default: /var/run/docker.sock
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'linux'
       queries:
         - |
           LET data = SELECT parse_json(data=Content) as JSON
           FROM http_client(url=dockerSocket + ":unix/info")
         - |
           SELECT JSON.ID as ID,
                  JSON.Containers as Containers,
                  JSON.ContainersRunning as ContainersRunning,
                  JSON.ContainersPaused as ContainersPaused,
                  JSON.ContainersStopped as ContainersStopped,
                  JSON.Images as Images,
                  JSON.Driver as Driver,
                  JSON.MemoryLimit as MemoryLimit,
                  JSON.SwapLimit as SwapLimit,
                  JSON.KernelMemory as KernelMemory,
                  JSON.CpuCfsPeriod as CpuCfsPeriod,
                  JSON.CpuCfsQuota as CpuCfsQuota,
                  JSON.CPUShares as CPUShares,
                  JSON.CPUSet as CPUSet,
                  JSON.IPv4Forwarding as IPv4Forwarding,
                  JSON.BridgeNfIptables as BridgeNfIptables,
                  JSON.BridgeNfIp6tables as BridgeNfIp6tables,
                  JSON.OomKillDisable as OomKillDisable,
                  JSON.LoggingDriver as LoggingDriver,
                  JSON.CgroupDriver as CgroupDriver,
                  JSON.KernelVersion as KernelVersion,
                  JSON.OperatingSystem as OperatingSystem,
                  JSON.OSType as OSType,
                  JSON.Architecture as Architecture,
                  JSON.NCPU as NCPU,
                  JSON.MemTotal as MemTotal,
                  JSON.HttpProxy as HttpProxy,
                  JSON.HttpsProxy as HttpsProxy,
                  JSON.NoProxy as NoProxy,
                  JSON.Name as Name,
                  JSON.ServerVersion as ServerVersion,
                  JSON.DockerRootDir as DockerRootDir
           FROM data

.. raw:: html

   </div></div>


.. |Linux_Applications_Docker_VersionDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Linux_Applications_Docker_VersionDetails" role="button"
     aria-expanded="false" aria-controls="Linux_Applications_Docker_VersionDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Linux.Applications.Docker.Version
*********************************
|Linux_Applications_Docker_VersionDetails| Get Dockers version by connecting to its socket.

.. raw:: html

  <div class="collapse" id="Linux_Applications_Docker_VersionDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Linux.Applications.Docker.Version
   description: Get Dockers version by connecting to its socket.
   parameters:
     - name: dockerSocket
       description: |
         Docker server socket. You will normally need to be root to connect.
       default: /var/run/docker.sock
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'linux'
       queries:
         - |
           LET data = SELECT parse_json(data=Content) as JSON
           FROM http_client(url=dockerSocket + ":unix/version")
         - |
           SELECT JSON.Version as Version,
                  JSON.ApiVersion as ApiVersion,
                  JSON.MinAPIVersion as MinAPIVersion,
                  JSON.GitCommit as GitCommit,
                  JSON.GoVersion as GoVersion,
                  JSON.Os as Os,
                  JSON.Arch as Arch,
                  JSON.KernelVersion as KernelVersion,
                  JSON.BuildTime as BuildTime
           FROM data

.. raw:: html

   </div></div>


.. |Linux_Debian_AptSourcesDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Linux_Debian_AptSourcesDetails" role="button"
     aria-expanded="false" aria-controls="Linux_Debian_AptSourcesDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Linux.Debian.AptSources
***********************
|Linux_Debian_AptSourcesDetails| Parse Debian apt sources.

We first search for \*.list files which contain lines of the form

.. code:: console

   deb http://us.archive.ubuntu.com/ubuntu/ bionic main restricted

For each line we construct the cache file by spliting off the
section (last component) and replacing / and " " with _.

We then try to open the file. If the file exists we parse some
metadata from it. If not we leave those columns empty.


.. raw:: html

  <div class="collapse" id="Linux_Debian_AptSourcesDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Linux.Debian.AptSources
   description: |
     Parse Debian apt sources.
   
     We first search for \*.list files which contain lines of the form
   
     .. code:: console
   
        deb http://us.archive.ubuntu.com/ubuntu/ bionic main restricted
   
     For each line we construct the cache file by spliting off the
     section (last component) and replacing / and " " with _.
   
     We then try to open the file. If the file exists we parse some
     metadata from it. If not we leave those columns empty.
   
   reference: "https://osquery.io/schema/3.2.6#apt_sources"
   parameters:
     - name: linuxAptSourcesGlobs
       description: Globs to find apt source *.list files.
       default: /etc/apt/sources.list,/etc/apt/sources.list.d/*.list
     - name:  aptCacheDirectory
       description: Location of the apt cache directory.
       default: /var/lib/apt/lists/
   sources:
     - precondition:
         SELECT OS From info() where OS = 'linux'
       queries:
          - |
            /* Search for files which may contain apt sources. The user can
               pass new globs here. */
            LET files = SELECT FullPath from glob(
              globs=split(string=linuxAptSourcesGlobs, sep=","))
   
          - |
            /* Read each line in the sources which is not commented.
               Deb lines look like:
               deb [arch=amd64] http://dl.google.com/linux/chrome-remote-desktop/deb/ stable main
               Contains URL, base_uri and components.
            */
            LET deb_sources = SELECT *
              FROM parse_records_with_regex(
                file=files.FullPath,
                regex="(?m)^ *(?P<Type>deb(-src)?) (?:\\[arch=(?P<Arch>[^\\]]+)\\] )?" +
                     "(?P<URL>https?://(?P<base_uri>[^ ]+))" +
                     " +(?P<components>.+)")
   
          - |
            /* We try to get at the Release file in /var/lib/apt/ by munging
              the components and URL.
              Strip the last component off, convert / and space to _ and
              add _Release to get the filename.
            */
            LET parsed_apt_lines = SELECT Arch, URL,
               base_uri + " " + components as Name, Type,
               FullPath as Source, aptCacheDirectory + regex_replace(
                 replace="_",
                 re="_+",
                 source=regex_replace(
                   replace="_", re="[ /]",
                   source=base_uri + "_dists_" + regex_replace(
                      source=components,
                      replace="", re=" +[^ ]+$")) + "_Release"
                 )  as cache_file
            FROM deb_sources
   
          - |
            /* This runs if the file was found. Read the entire file into
               memory and parse the same record using multiple RegExps.
            */
            LET parsed_cache_files = SELECT Name, Arch, URL, Type,
              Source, parse_string_with_regex(
                   string=Record,
                   regex=["Codename: (?P<Release>[^\\s]+)",
                          "Version: (?P<Version>[^\\s]+)",
                          "Origin: (?P<Maintainer>[^\\s]+)",
                          "Architectures: (?P<Architectures>[^\\s]+)",
                          "Components: (?P<Components>[^\\s]+)"]) as Record
              FROM parse_records_with_regex(file=cache_file, regex="(?sm)(?P<Record>.+)")
   
          - |
            // Foreach row in the parsed cache file, collect the FileInfo too.
            LET add_stat_to_parsed_cache_file = SELECT * from foreach(
              query={
                SELECT FullPath, Mtime, Ctime, Atime, Record, Type,
                  Name, Arch, URL, Source from stat(filename=cache_file)
              }, row=parsed_cache_files)
   
          - |
            /* For each row in the parsed file, run the appropriate query
               depending on if the cache file exists.
               If the cache file is not found, we just copy the lines we
               parsed from the source file and fill in empty values for
               stat.
            */
            LET parse_cache_or_pass = SELECT * from if(
              condition={
                 SELECT * from stat(filename=cache_file)
              },
              then=add_stat_to_parsed_cache_file,
              else={
              SELECT Source, Null as Mtime, Null as Ctime,
                  Null as Atime, Type,
                  Null as Record, Arch, URL, Name from scope()
              })
   
          - |
            -- For each parsed apt .list file line produce some output.
            SELECT * from foreach(
                row=parsed_apt_lines,
                query=parse_cache_or_pass)

.. raw:: html

   </div></div>


.. |Linux_Debian_PackagesDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Linux_Debian_PackagesDetails" role="button"
     aria-expanded="false" aria-controls="Linux_Debian_PackagesDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Linux.Debian.Packages
*********************
|Linux_Debian_PackagesDetails| Parse dpkg status file.

.. raw:: html

  <div class="collapse" id="Linux_Debian_PackagesDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Linux.Debian.Packages
   description: Parse dpkg status file.
   parameters:
     - name: linuxDpkgStatus
       default: /var/lib/dpkg/status
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'linux'
       queries:
         - |
           /* First pass - split file into records start with
              Package and end with \n\n.
   
              Then parse each record using multiple RegExs.
           */
           LET packages = SELECT parse_string_with_regex(
               string=Record,
               regex=['Package:\\s(?P<Package>.+)',
                      'Installed-Size:\\s(?P<InstalledSize>.+)',
                      'Version:\\s(?P<Version>.+)',
                      'Source:\\s(?P<Source>.+)',
                      'Architecture:\\s(?P<Architecture>.+)']) as Record
               FROM parse_records_with_regex(
                      file=linuxDpkgStatus,
                      regex='(?sm)^(?P<Record>Package:.+?)\\n\\n')
         - |
           SELECT Record.Package as Package,
                  atoi(string=Record.InstalledSize) as InstalledSize,
                  Record.Version as Version,
                  Record.Source as Source,
                  Record.Architecture as Architecture from packages

.. raw:: html

   </div></div>


.. |Linux_MountsDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Linux_MountsDetails" role="button"
     aria-expanded="false" aria-controls="Linux_MountsDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Linux.Mounts
************
|Linux_MountsDetails| List mounted filesystems by reading /proc/mounts

.. raw:: html

  <div class="collapse" id="Linux_MountsDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Linux.Mounts
   description: List mounted filesystems by reading /proc/mounts
   parameters:
     - name: ProcMounts
       default: /proc/mounts
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'linux'
       queries:
         - |
           SELECT Device, Mount, FSType, split(string=Opts, sep=",") As Options
                  FROM parse_records_with_regex(
                      file=ProcMounts,
                      regex='(?m)^(?P<Device>[^ ]+) (?P<Mount>[^ ]+) (?P<FSType>[^ ]+) '+
                            '(?P<Opts>[^ ]+)')

.. raw:: html

   </div></div>


.. |Linux_Proc_ArpDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Linux_Proc_ArpDetails" role="button"
     aria-expanded="false" aria-controls="Linux_Proc_ArpDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Linux.Proc.Arp
**************
|Linux_Proc_ArpDetails| ARP table via /proc/net/arp.

.. raw:: html

  <div class="collapse" id="Linux_Proc_ArpDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Linux.Proc.Arp
   description: ARP table via /proc/net/arp.
   parameters:
     - name: ProcNetArp
       default: /proc/net/arp
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'linux'
   
       queries:
         - |
           SELECT * from split_records(
              filenames=ProcNetArp,
              regex='\\s{3,20}',
              first_row_is_headers=true)

.. raw:: html

   </div></div>


.. |Linux_Proc_ModulesDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Linux_Proc_ModulesDetails" role="button"
     aria-expanded="false" aria-controls="Linux_Proc_ModulesDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Linux.Proc.Modules
******************
|Linux_Proc_ModulesDetails| Module listing via /proc/modules.

.. raw:: html

  <div class="collapse" id="Linux_Proc_ModulesDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Linux.Proc.Modules
   description: Module listing via /proc/modules.
   parameters:
     - name: ProcModules
       default: /proc/modules
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'linux'
   
       queries:
         - |
           SELECT Name,
             atoi(string=Size) As Size,
             atoi(string=UseCount) As UseCount,
             Status, Address
           FROM split_records(
              filenames=ProcModules,
              regex='\\s+',
              columns=['Name', 'Size', 'UseCount', 'UsedBy', 'Status', 'Address'])

.. raw:: html

   </div></div>


.. |Linux_Ssh_AuthorizedKeysDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Linux_Ssh_AuthorizedKeysDetails" role="button"
     aria-expanded="false" aria-controls="Linux_Ssh_AuthorizedKeysDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Linux.Ssh.AuthorizedKeys
************************
|Linux_Ssh_AuthorizedKeysDetails| Find and parse ssh authorized keys files.

.. raw:: html

  <div class="collapse" id="Linux_Ssh_AuthorizedKeysDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Linux.Ssh.AuthorizedKeys
   description: Find and parse ssh authorized keys files.
   parameters:
     - name: sshKeyFiles
       default: '.ssh/authorized_keys*'
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'linux'
       queries:
         - |
           // For each user on the system, search for authorized_keys files.
           LET authorized_keys = SELECT * from foreach(
             row={
                SELECT Uid, User, Homedir from Artifact.Linux.Sys.Users()
             },
             query={
                SELECT FullPath, Mtime, Ctime, User, Uid from glob(
                  globs=Homedir + '/' + sshKeyFiles)
             })
         - |
           // For each authorized keys file, extract each line on a different row.
           // Note: This duplicates the path, user and uid on each key line.
           SELECT * from foreach(
             row=authorized_keys,
             query={
               SELECT Uid, User, FullPath, Key from split_records(
                  filenames=FullPath, regex="\n", columns=["Key"])
             })

.. raw:: html

   </div></div>


.. |Linux_Ssh_KnownHostsDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Linux_Ssh_KnownHostsDetails" role="button"
     aria-expanded="false" aria-controls="Linux_Ssh_KnownHostsDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Linux.Ssh.KnownHosts
********************
|Linux_Ssh_KnownHostsDetails| Find and parse ssh known hosts files.

.. raw:: html

  <div class="collapse" id="Linux_Ssh_KnownHostsDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Linux.Ssh.KnownHosts
   description: Find and parse ssh known hosts files.
   parameters:
     - name: sshKnownHostsFiles
       default: '.ssh/known_hosts*'
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'linux'
       queries:
         - |
           // For each user on the system, search for known_hosts files.
           LET authorized_keys = SELECT * from foreach(
             row={
                SELECT Uid, User, Homedir from Artifact.Linux.Sys.Users()
             },
             query={
                SELECT FullPath, Mtime, Ctime, User, Uid from glob(
                  globs=Homedir + '/' + sshKnownHostsFiles)
             })
         - |
           // For each known_hosts file, extract each line on a different row.
           SELECT * from foreach(
             row=authorized_keys,
             query={
               SELECT Uid, User, FullPath, Line from split_records(
                  filenames=FullPath, regex="\n", columns=["Line"])
               /* Ignore comment lines. */
               WHERE not Line =~ "^[^#]+#"
             })

.. raw:: html

   </div></div>


.. |Linux_Sys_ACPITablesDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Linux_Sys_ACPITablesDetails" role="button"
     aria-expanded="false" aria-controls="Linux_Sys_ACPITablesDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Linux.Sys.ACPITables
********************
|Linux_Sys_ACPITablesDetails| Firmware ACPI functional table common metadata and content.

.. raw:: html

  <div class="collapse" id="Linux_Sys_ACPITablesDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Linux.Sys.ACPITables
   description: Firmware ACPI functional table common metadata and content.
   reference: https://osquery.io/schema/3.2.6#acpi_tables
   parameters:
     - name: kLinuxACPIPath
       default: /sys/firmware/acpi/tables
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'linux'
       queries:
         - |
           LET hashes = SELECT Name, Size, hash(path=FullPath) as Hash
                        FROM glob(globs=kLinuxACPIPath + '/*')
         - |
           SELECT Name, Size, Hash.MD5, Hash.SHA1, Hash.SHA256 from hashes

.. raw:: html

   </div></div>


.. |Linux_Sys_CPUTimeDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Linux_Sys_CPUTimeDetails" role="button"
     aria-expanded="false" aria-controls="Linux_Sys_CPUTimeDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Linux.Sys.CPUTime
*****************
|Linux_Sys_CPUTimeDetails| Displays information from /proc/stat file about the time the cpu
cores spent in different parts of the system.


.. raw:: html

  <div class="collapse" id="Linux_Sys_CPUTimeDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Linux.Sys.CPUTime
   description: |
     Displays information from /proc/stat file about the time the cpu
     cores spent in different parts of the system.
   parameters:
     - name: procStat
       default: /proc/stat
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'linux'
       queries:
         - |
           LET raw = SELECT * FROM split_records(
              filenames=procStat,
              regex=' +',
              columns=['core', 'user', 'nice', 'system',
                       'idle', 'iowait', 'irq', 'softirq',
                       'steal', 'guest', 'guest_nice'])
           WHERE core =~ 'cpu.+'
         - |
           SELECT core AS Core,
                  atoi(string=user) as User,
                  atoi(string=nice) as Nice,
                  atoi(string=system) as System,
                  atoi(string=idle) as Idle,
                  atoi(string=iowait) as IOWait,
                  atoi(string=irq) as IRQ,
                  atoi(string=softirq) as SoftIRQ,
                  atoi(string=steal) as Steal,
                  atoi(string=guest) as Guest,
                  atoi(string=guest_nice) as GuestNice FROM raw

.. raw:: html

   </div></div>


.. |Linux_Sys_CrontabDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Linux_Sys_CrontabDetails" role="button"
     aria-expanded="false" aria-controls="Linux_Sys_CrontabDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Linux.Sys.Crontab
*****************
|Linux_Sys_CrontabDetails| Displays parsed information from crontab.


.. raw:: html

  <div class="collapse" id="Linux_Sys_CrontabDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Linux.Sys.Crontab
   description: |
     Displays parsed information from crontab.
   parameters:
     - name: cronTabGlob
       default: /etc/crontab,/etc/cron.d/**,/var/at/tabs/**,/var/spool/cron/**,/var/spool/cron/crontabs/**
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'linux'
       queries:
         - |
           LET raw = SELECT * FROM foreach(
             row={
               SELECT FullPath from glob(globs=split(string=cronTabGlob, sep=","))
             },
             query={
               SELECT FullPath, data, parse_string_with_regex(
                 string=data,
                 regex=[
                    /* Regex for event (Starts with @) */
                    "^(?P<Event>@[a-zA-Z]+)\\s+(?P<Command>.+)",
   
                    /* Regex for regular command. */
                    "^(?P<Minute>[^\\s]+)\\s+"+
                    "(?P<Hour>[^\\s]+)\\s+"+
                    "(?P<DayOfMonth>[^\\s]+)\\s+"+
                    "(?P<Month>[^\\s]+)\\s+"+
                    "(?P<DayOfWeek>[^\\s]+)\\s+"+
                    "(?P<Command>.+)$"]) as Record
   
               /* Read lines from the file and filter ones that start with "#" */
               FROM split_records(
                  filenames=FullPath,
                  regex="\n", columns=["data"]) WHERE not data =~ "^\\s*#"
               }) WHERE Record.Command
   
         - |
           SELECT Record.Event AS Event,
                  Record.Minute AS Minute,
                  Record.Hour AS Hour,
                  Record.DayOfMonth AS DayOfMonth,
                  Record.Month AS Month,
                  Record.DayOfWeek AS DayOfWeek,
                  Record.Command AS Command,
                  FullPath AS Path
           FROM raw

.. raw:: html

   </div></div>


.. |Linux_Sys_LastUserLoginDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Linux_Sys_LastUserLoginDetails" role="button"
     aria-expanded="false" aria-controls="Linux_Sys_LastUserLoginDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Linux.Sys.LastUserLogin
***********************
|Linux_Sys_LastUserLoginDetails| Find and parse system wtmp files. This indicate when the user last logged in.

.. raw:: html

  <div class="collapse" id="Linux_Sys_LastUserLoginDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Linux.Sys.LastUserLogin
   description: Find and parse system wtmp files. This indicate when the
                user last logged in.
   parameters:
     - name: wtmpGlobs
       default: /var/log/wtmp*
   
       # This is automatically generated from dwarf symbols by Rekall:
       # gcc -c -g -o /tmp/test.o /tmp/1.c
       # rekall dwarfparser /tmp/test.o
   
       # And 1.c is:
       # #include "utmp.h"
       # struct utmp x;
   
     - name: wtmpProfile
       default: |
          {
            "timeval": [8, {
             "tv_sec": [0, ["int"]],
             "tv_usec": [4, ["int"]]
            }],
            "exit_status": [4, {
             "e_exit": [2, ["short int"]],
             "e_termination": [0, ["short int"]]
            }],
            "timezone": [8, {
             "tz_dsttime": [4, ["int"]],
             "tz_minuteswest": [0, ["int"]]
            }],
            "utmp": [384, {
             "__glibc_reserved": [364, ["Array", {
              "count": 20,
              "target": "char",
              "target_args": null
             }]],
             "ut_addr_v6": [348, ["Array", {
              "count": 4,
              "target": "int",
              "target_args": null
             }]],
             "ut_exit": [332, ["exit_status"]],
             "ut_host": [76, ["String", {
              "length": 256
             }]],
             "ut_id": [40, ["String", {
              "length": 4
             }]],
             "ut_line": [8, ["String", {
              "length": 32
             }]],
             "ut_pid": [4, ["int"]],
             "ut_session": [336, ["int"]],
             "ut_tv": [340, ["timeval"]],
             "ut_type": [0, ["Enumeration", {
               "target": "short int",
               "choices": {
                  "0": "EMPTY",
                  "1": "RUN_LVL",
                  "2": "BOOT_TIME",
                  "5": "INIT_PROCESS",
                  "6": "LOGIN_PROCESS",
                  "7": "USER_PROCESS",
                  "8": "DEAD_PROCESS"
                }
             }]],
             "ut_user": [44, ["String", {
              "length": 32
             }]]
            }]
          }
   
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'linux'
       queries:
         - |
           SELECT * from foreach(
             row={
               SELECT FullPath from glob(globs=split(string=wtmpGlobs, sep=","))
             },
             query={
               SELECT ut_type, ut_id, ut_host.AsString as Host,
                      ut_user.AsString as User,
                      timestamp(epoch=ut_tv.tv_sec.AsInteger) as login_time
               FROM binary_parse(
                      file=FullPath,
                      profile=wtmpProfile,
                      target="Array",
                      args=dict(Target="utmp")
                    )
             })

.. raw:: html

   </div></div>


.. |Linux_Sys_UsersDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Linux_Sys_UsersDetails" role="button"
     aria-expanded="false" aria-controls="Linux_Sys_UsersDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Linux.Sys.Users
***************
|Linux_Sys_UsersDetails| Get User specific information like homedir, group etc from /etc/passwd.

.. raw:: html

  <div class="collapse" id="Linux_Sys_UsersDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Linux.Sys.Users
   description: Get User specific information like homedir, group etc from /etc/passwd.
   parameters:
     - name: PasswordFile
       default: /etc/passwd
       description: The location of the password file.
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'linux'
       queries:
         - |
           SELECT User, Description, Uid, Gid, Homedir, Shell
             FROM parse_records_with_regex(
               file=PasswordFile,
               regex='(?m)^(?P<User>[^:]+):([^:]+):' +
                     '(?P<Uid>[^:]+):(?P<Gid>[^:]+):(?P<Description>[^:]*):' +
                     '(?P<Homedir>[^:]+):(?P<Shell>[^:\\s]+)')

.. raw:: html

   </div></div>


.. |Network_ExternalIpAddressDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Network_ExternalIpAddressDetails" role="button"
     aria-expanded="false" aria-controls="Network_ExternalIpAddressDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Network.ExternalIpAddress
*************************
|Network_ExternalIpAddressDetails| Detect the external ip address of the end point.

.. raw:: html

  <div class="collapse" id="Network_ExternalIpAddressDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Network.ExternalIpAddress
   description: Detect the external ip address of the end point.
   parameters:
     - name: externalUrl
       default: http://www.myexternalip.com/raw
       description: The URL of the external IP detection site.
   sources:
     - precondition: SELECT * from info()
       queries:
         - SELECT Content as IP from http_client(url=externalUrl)

.. raw:: html

   </div></div>


.. |Reporting_Hunts_DetailsDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Reporting_Hunts_DetailsDetails" role="button"
     aria-expanded="false" aria-controls="Reporting_Hunts_DetailsDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Reporting.Hunts.Details
***********************
|Reporting_Hunts_DetailsDetails| Report details about which client ran each hunt, how long it took
and if it has completed.


.. raw:: html

  <div class="collapse" id="Reporting_Hunts_DetailsDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Reporting.Hunts.Details
   description: |
     Report details about which client ran each hunt, how long it took
     and if it has completed.
   
   sources:
     - precondition:
         SELECT server_config FROM scope()
   
       queries:
         - |
           LET hunts = SELECT basename(path=hunt_id) as hunt_id,
               create_time,
               hunt_description
           FROM hunts() order by create_time desc limit 6
         - |
           LET flows = select hunt_id,
             hunt_description,
             Fqdn,
             ClientId,
             { SELECT os_info.system FROM clients(search=ClientId) } as OS,
             timestamp(epoch=Flow.FlowContext.create_time/1000000) as create_time,
             basename(path=Flow.Urn) as flow_id,
             (Flow.FlowContext.active_time - Flow.FlowContext.create_time) / 1000000 as Duration,
             format(format='%v', args=[Flow.FlowContext.state]) as State
           FROM hunt_flows(hunt_id=hunt_id) order by create_time desc
         - |
           SELECT * from foreach(row=hunts, query=flows)

.. raw:: html

   </div></div>


.. |Server_Alerts_InteractiveShellDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Server_Alerts_InteractiveShellDetails" role="button"
     aria-expanded="false" aria-controls="Server_Alerts_InteractiveShellDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Server.Alerts.InteractiveShell
******************************
|Server_Alerts_InteractiveShellDetails| Velociraptor's interactive shell is a powerful feature. If you want
to monitor use of the shell on any clients, simply collect this
artifact.


.. raw:: html

  <div class="collapse" id="Server_Alerts_InteractiveShellDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Server.Alerts.InteractiveShell
   description: |
     Velociraptor's interactive shell is a powerful feature. If you want
     to monitor use of the shell on any clients, simply collect this
     artifact.
   
   sources:
     - queries:
         - |
           SELECT * from watch_monitoring(artifact='Shell')

.. raw:: html

   </div></div>


.. |Server_Alerts_PsExecDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Server_Alerts_PsExecDetails" role="button"
     aria-expanded="false" aria-controls="Server_Alerts_PsExecDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Server.Alerts.PsExec
********************
|Server_Alerts_PsExecDetails| Send an email if execution of the psexec service was detected on
any client. This is a server side artifact.

Note this requires that the Windows.Event.ProcessCreation
monitoring artifact be collected from clients.


.. raw:: html

  <div class="collapse" id="Server_Alerts_PsExecDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Server.Alerts.PsExec
   description: |
      Send an email if execution of the psexec service was detected on
      any client. This is a server side artifact.
   
      Note this requires that the Windows.Event.ProcessCreation
      monitoring artifact be collected from clients.
   
   parameters:
     - name: EmailAddress
       default: admin@example.com
     - name: MessageTemplate
       default: |
         PsExec execution detected at %v: %v for client %v
   
   sources:
     - queries:
         - |
           SELECT * FROM foreach(
             row={
               SELECT * from watch_monitoring(
                 artifact='Windows.Events.ProcessCreation')
               WHERE Name =~ '(?i)psexesvc'
             },
             query={
               SELECT * FROM mail(
                 to=EmailAddress,
                 subject='PsExec launched on host',
                 period=60,
                 body=format(
                 format=MessageTemplate,
                 args=[Timestamp, CommandLine, ClientId])
             )
           })

.. raw:: html

   </div></div>


.. |Server_Hunts_ListDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Server_Hunts_ListDetails" role="button"
     aria-expanded="false" aria-controls="Server_Hunts_ListDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Server.Hunts.List
*****************
|Server_Hunts_ListDetails| List Hunts currently scheduled on the server.


.. raw:: html

  <div class="collapse" id="Server_Hunts_ListDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Server.Hunts.List
   description: |
     List Hunts currently scheduled on the server.
   
   sources:
     - precondition:
         SELECT * from server_config
   
       queries:
         - |
           SELECT HuntId, timestamp(epoch=create_time/1000000) as Created,
                  start_request.Args.artifacts.names  as Artifact,
                  State
           FROM hunts()
           WHERE start_request.flow_name = 'ArtifactCollector'

.. raw:: html

   </div></div>


.. |Server_Hunts_ResultsDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Server_Hunts_ResultsDetails" role="button"
     aria-expanded="false" aria-controls="Server_Hunts_ResultsDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Server.Hunts.Results
********************
|Server_Hunts_ResultsDetails| Show the results from each artifact collection hunt.


.. raw:: html

  <div class="collapse" id="Server_Hunts_ResultsDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Server.Hunts.Results
   description: |
     Show the results from each artifact collection hunt.
   parameters:
     - name: huntId
       default: H.d05b2482
     - name: ArtifactName
       default: Linux.Mounts
   
   sources:
     - precondition:
         SELECT * from server_config
   
       queries:
         - |
           SELECT * FROM hunt_results(hunt_id=huntId, artifact=ArtifactName)

.. raw:: html

   </div></div>


.. |Windows_Applications_ChocolateyPackagesDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Applications_ChocolateyPackagesDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Applications_ChocolateyPackagesDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Applications.ChocolateyPackages
***************************************
|Windows_Applications_ChocolateyPackagesDetails| Chocolatey packages installed in a system.

.. raw:: html

  <div class="collapse" id="Windows_Applications_ChocolateyPackagesDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Applications.ChocolateyPackages
   description: Chocolatey packages installed in a system.
   parameters:
     - name: ChocolateyInstall
       default: ""
   
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           LET files =
             SELECT FullPath, parse_xml(file=FullPath) AS Metadata
             -- Use the ChocolateyInstall parameter if it is set.
             FROM glob(globs=if(
                condition=ChocolateyInstall,
                then=ChocolateyInstall,
                -- Otherwise just use the environment.
                else=environ(var='ChocolateyInstall')) + '/lib/*/*.nuspec')
         - |
           SELECT * FROM if(
           condition={
               SELECT * FROM if(
                  condition=ChocolateyInstall,
                  then=ChocolateyInstall,
                  else=environ(var="ChocolateyInstall"))
             },
           then={
               SELECT FullPath,
                      Metadata.package.metadata.id as Name,
                      Metadata.package.metadata.version as Version,
                      Metadata.package.metadata.summary as Summary,
                      Metadata.package.metadata.authors as Authors,
                      Metadata.package.metadata.licenseUrl as License
               FROM files
           })

.. raw:: html

   </div></div>


.. |Windows_Applications_Chrome_ExtensionsDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Applications_Chrome_ExtensionsDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Applications_Chrome_ExtensionsDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Applications.Chrome.Extensions
**************************************
|Windows_Applications_Chrome_ExtensionsDetails| Fetch Chrome extensions.

Chrome extensions are installed into the user's home directory.  We
search for manifest.json files in a known path within each system
user's home directory. We then parse the manifest file as JSON.

Many extensions use locale packs to resolve strings like name and
description. In this case we detect the default locale and load
those locale files. We then resolve the extension's name and
description from there.


.. raw:: html

  <div class="collapse" id="Windows_Applications_Chrome_ExtensionsDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Applications.Chrome.Extensions
   description: |
     Fetch Chrome extensions.
   
     Chrome extensions are installed into the user's home directory.  We
     search for manifest.json files in a known path within each system
     user's home directory. We then parse the manifest file as JSON.
   
     Many extensions use locale packs to resolve strings like name and
     description. In this case we detect the default locale and load
     those locale files. We then resolve the extension's name and
     description from there.
   
   parameters:
     - name: extensionGlobs
       default: \AppData\Local\Google\Chrome\User Data\*\Extensions\*\*\manifest.json
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           /* For each user on the system, search for extension manifests
              in their home directory. */
           LET extension_manifests = SELECT * from foreach(
             row={
                SELECT Uid, Name AS User, Directory from Artifact.Windows.Sys.Users()
             },
             query={
                SELECT FullPath, Mtime, Ctime, User, Uid from glob(
                  globs=Directory + extensionGlobs)
             })
   
         - |
           /* If the Manifest declares a default_locale then we
              load and parse the messages file. In this case the
              messages are actually stored in the locale file
              instead of the main manifest.json file.
           */
           LET maybe_read_locale_file =
              SELECT * from if(
                 condition={
                    select * from scope() where Manifest.default_locale
                 },
                 then={
                    SELECT Manifest,
                           Uid, User,
                           Filename as LocaleFilename,
                           ManifestFilename,
                           parse_json(data=Data) AS LocaleManifest
                    FROM read_file(
                            -- Munge the filename to get the messages.json path.
                            filenames=regex_replace(
                              source=ManifestFilename,
                              replace="\\_locales\\" + Manifest.default_locale +
                                      "\\messages.json",
                              re="\\\\manifest.json$"))
                 },
                 else={
                     -- Just fill in empty Locale results.
                     SELECT Manifest,
                            Uid, User,
                            "" AS LocaleFilename,
                            "" AS ManifestFilename,
                            "" AS LocaleManifest
                     FROM scope()
                 })
   
         - |
           LET parse_json_files = SELECT * from foreach(
              row={
                SELECT Filename as ManifestFilename,
                       Uid, User,
                       parse_json(data=Data) as Manifest
                FROM read_file(filenames=FullPath)
              },
              query=maybe_read_locale_file)
   
         - |
           LET parsed_manifest_files = SELECT * from foreach(
             row=extension_manifests,
             query=parse_json_files)
   
         - |
           SELECT Uid, User,
   
                  /* If the manifest name contains __MSG_ then the real
                     name is stored in the locale manifest. This condition
                     resolves the Name column either to the main manifest or
                     the locale manifest.
                  */
                  if(condition="__MSG_" in Manifest.name,
                     then=get(item=LocaleManifest,
                        member=regex_replace(
                           source=Manifest.name,
                           replace="$1",
                           re="(?:__MSG_(.+)__)")).message,
                     else=Manifest.name) as Name,
   
                  if(condition="__MSG_" in Manifest.description,
                     then=get(item=LocaleManifest,
                        member=regex_replace(
                           source=Manifest.description,
                           replace="$1",
                           re="(?:__MSG_(.+)__)")).message,
                     else=Manifest.description) as Description,
   
                  /* Get the Identifier and Version from the manifest filename */
                  regex_replace(
                    source=ManifestFilename,
                    replace="$1",
                    re="(?:.+Extensions\\\\([^\\\\]+)\\\\([^\\\\]+)\\\\manifest.json)$") AS Identifier,
                  regex_replace(
                    source=ManifestFilename,
                    replace="$2",
                    re="(?:.+Extensions\\\\([^\\\\]+)\\\\([^\\\\]+)\\\\manifest.json)$") AS Version,
   
                  Manifest.author as Author,
                  Manifest.background.persistent AS Persistent,
                  regex_replace(
                    source=ManifestFilename,
                    replace="$1",
                    re="(.+Extensions\\\\.+\\\\)manifest.json$") AS Path,
   
                  Manifest.oauth2.scopes as Scopes,
                  Manifest.permissions as Permissions,
                  Manifest.key as Key
   
           FROM parsed_manifest_files

.. raw:: html

   </div></div>


.. |Windows_Applications_OfficeMacrosDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Applications_OfficeMacrosDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Applications_OfficeMacrosDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Applications.OfficeMacros
*********************************
|Windows_Applications_OfficeMacrosDetails| Office macros are a favourite initial infection vector. Many users
click through the warning dialogs.

This artifact scans through the given directory glob for common
office files. We then try to extract any embedded macros by parsing
the OLE file structure.

If a macro calls an external program (e.g. Powershell) this is very
suspicious!


.. raw:: html

  <div class="collapse" id="Windows_Applications_OfficeMacrosDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Applications.OfficeMacros
   description: |
     Office macros are a favourite initial infection vector. Many users
     click through the warning dialogs.
   
     This artifact scans through the given directory glob for common
     office files. We then try to extract any embedded macros by parsing
     the OLE file structure.
   
     If a macro calls an external program (e.g. Powershell) this is very
     suspicious!
   
   parameters:
     - name: officeExtensions
       default: "*.{xls,xlsm,doc,docx,ppt,pptm}"
     - name: officeFileSearchGlob
       default: C:\Users\**\
       description: The directory to search for office documents.
   
   sources:
     - queries:
         - |
           SELECT * FROM foreach(
              row={
                 SELECT FullPath FROM glob(globs=officeFileSearchGlob + officeExtensions)
              },
              query={
                  SELECT * from olevba(file=FullPath)
              })

.. raw:: html

   </div></div>


.. |Windows_Events_DNSQueriesDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Events_DNSQueriesDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Events_DNSQueriesDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Events.DNSQueries
*************************
|Windows_Events_DNSQueriesDetails| Monitor all DNS Queries and responses.

This artifact monitors all DNS queries and their responses seen on
the endpoint. DNS is a critical source of information for intrusion
detection and the best place to collect it is on the endpoint itself
(Perimeter collection can only see DNS requests while the endpoint
or laptop is inside the enterprise network).

It is recommended to collect this artifact and just archive the
results. When threat intelligence emerges about a watering hole or a
bad C&C you can use this archive to confirm if any of your endpoints
have contacted this C&C.


.. raw:: html

  <div class="collapse" id="Windows_Events_DNSQueriesDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Events.DNSQueries
   description: |
     Monitor all DNS Queries and responses.
   
     This artifact monitors all DNS queries and their responses seen on
     the endpoint. DNS is a critical source of information for intrusion
     detection and the best place to collect it is on the endpoint itself
     (Perimeter collection can only see DNS requests while the endpoint
     or laptop is inside the enterprise network).
   
     It is recommended to collect this artifact and just archive the
     results. When threat intelligence emerges about a watering hole or a
     bad C&C you can use this archive to confirm if any of your endpoints
     have contacted this C&C.
   
   parameters:
     - name: whitelistRegex
       description: We ignore DNS names that match this regex.
       default: wpad.home
   
   sources:
    - precondition:
        SELECT OS from info() where OS = "windows"
   
      queries:
         - |
           SELECT timestamp(epoch=Time) As Time, EventType, Name, CNAME, Answers
           FROM dns()
           WHERE not Name =~ whitelistRegex

.. raw:: html

   </div></div>


.. |Windows_Events_FailedLogBeforeSuccessDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Events_FailedLogBeforeSuccessDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Events_FailedLogBeforeSuccessDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Events.FailedLogBeforeSuccess
*************************************
|Windows_Events_FailedLogBeforeSuccessDetails| Sometimes attackers will brute force an local user's account's
password. If the account password is strong, brute force attacks are
not effective and might not represent a high value event in
themselves.

However, if the brute force attempt succeeds, then it is a very high
value event (since brute forcing a password is typically a
suspicious activity).

On the endpoint this looks like a bunch of failed logon attempts in
quick succession followed by a successful login.

NOTE: In order for this artifact to work we need Windows to be
logging failed account login. This is not on by default and should
be enabled via group policy.

https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events

You can set the policy in group policy managment console (gpmc):
Computer Configuration\Windows Settings\Security Settings\Local Policies\Audit Policy.


.. raw:: html

  <div class="collapse" id="Windows_Events_FailedLogBeforeSuccessDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Events.FailedLogBeforeSuccess
   description: |
     Sometimes attackers will brute force an local user's account's
     password. If the account password is strong, brute force attacks are
     not effective and might not represent a high value event in
     themselves.
   
     However, if the brute force attempt succeeds, then it is a very high
     value event (since brute forcing a password is typically a
     suspicious activity).
   
     On the endpoint this looks like a bunch of failed logon attempts in
     quick succession followed by a successful login.
   
     NOTE: In order for this artifact to work we need Windows to be
     logging failed account login. This is not on by default and should
     be enabled via group policy.
   
     https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events
   
     You can set the policy in group policy managment console (gpmc):
     Computer Configuration\Windows Settings\Security Settings\Local Policies\Audit Policy.
   
   parameters:
     - name: securityLogFile
       default: >-
         C:/Windows/System32/Winevt/Logs/Security.evtx
   
     - name: failureCount
       description: Alert if there are this many failures before the successful logon.
       default: 3
   
     - name: failedLogonTimeWindow
       default: 3600
   
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           LET failed_logon = SELECT EventData as FailedEventData,
              System as FailedSystem
           FROM watch_evtx(filename=securityLogFile)
           WHERE System.EventID = '4625'
   
         - |
           LET last_5_events = SELECT FailedEventData, FailedSystem
               FROM fifo(query=failed_logon,
                         max_rows=500,
                         max_age=atoi(string=failedLogonTimeWindow))
   
         # Force the fifo to materialize.
         - LET foo <= SELECT * FROM last_5_events
   
         - |
           LET success_logon = SELECT EventData as SuccessEventData,
              System as SuccessSystem
           FROM watch_evtx(filename=securityLogFile)
           WHERE System.EventID = '4624'
   
         - |
           SELECT * FROM foreach(
             row=success_logon,
             query={
              SELECT SuccessSystem.TimeCreated.SystemTime AS LogonTime,
                     SuccessSystem, SuccessEventData, FailedEventData,
                     FailedSystem, count(items=SuccessSystem) as Count
              FROM last_5_events
              WHERE FailedEventData.SubjectUserName = SuccessEventData.SubjectUserName
              GROUP BY LogonTime
             })  WHERE Count > atoi(string=failureCount)

.. raw:: html

   </div></div>


.. |Windows_Events_ProcessCreationDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Events_ProcessCreationDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Events_ProcessCreationDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Events.ProcessCreation
******************************
|Windows_Events_ProcessCreationDetails| Collect all process creation events.


.. raw:: html

  <div class="collapse" id="Windows_Events_ProcessCreationDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Events.ProcessCreation
   description: |
     Collect all process creation events.
   parameters:
     - name: wmiQuery
       default: SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE
         TargetInstance ISA 'Win32_Process'
     - name: eventQuery
       default: SELECT * FROM Win32_ProcessStartTrace
   
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           // Convert the timestamp from WinFileTime to Epoch.
           SELECT timestamp(epoch=atoi(string=Parse.TIME_CREATED) / 10000000 - 11644473600 ) as Timestamp,
                  Parse.ParentProcessID as PPID,
                  Parse.ProcessID as PID,
                  Parse.ProcessName as Name, {
                    SELECT CommandLine
                    FROM wmi(
                      query="SELECT * FROM Win32_Process WHERE ProcessID = " +
                       format(format="%v", args=Parse.ProcessID),
                      namespace="ROOT/CIMV2")
                  } AS CommandLine
           FROM wmi_events(
              query=eventQuery,
              wait=5000000,   // Do not time out.
              namespace="ROOT/CIMV2")

.. raw:: html

   </div></div>


.. |Windows_Events_ServiceCreationDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Events_ServiceCreationDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Events_ServiceCreationDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Events.ServiceCreation
******************************
|Windows_Events_ServiceCreationDetails| Monitor for creation of new services.

New services are typically created by installing new software or
kernel drivers. Attackers will sometimes install a new service to
either insert a malicious kernel driver or as a persistence
mechanism.

This event monitor extracts the service creation events from the
event log and records them on the server.


.. raw:: html

  <div class="collapse" id="Windows_Events_ServiceCreationDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Events.ServiceCreation
   description: |
     Monitor for creation of new services.
   
     New services are typically created by installing new software or
     kernel drivers. Attackers will sometimes install a new service to
     either insert a malicious kernel driver or as a persistence
     mechanism.
   
     This event monitor extracts the service creation events from the
     event log and records them on the server.
   parameters:
     - name: systemLogFile
       default: >-
         C:/Windows/System32/Winevt/Logs/System.evtx
   
   sources:
    - precondition:
        SELECT OS from info() where OS = "windows"
   
      queries:
         - |
           SELECT System.TimeCreated.SystemTime as Timestamp,
                  System.EventID.Value as EventID,
                  EventData.ImagePath as ImagePath,
                  EventData.ServiceName as ServiceName,
                  EventData.ServiceType as Type,
                  System.Security.UserID as UserSID,
                  EventData as _EventData,
                  System as _System
           FROM watch_evtx(filename=systemLogFile) WHERE EventID = 7045

.. raw:: html

   </div></div>


.. |Windows_Network_ArpCacheDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Network_ArpCacheDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Network_ArpCacheDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Network.ArpCache
************************
|Windows_Network_ArpCacheDetails| Address resolution cache, both static and dynamic (from ARP, NDP).

.. raw:: html

  <div class="collapse" id="Windows_Network_ArpCacheDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Network.ArpCache
   description: Address resolution cache, both static and dynamic (from ARP, NDP).
   parameters:
     - name: wmiQuery
       default: |
         SELECT AddressFamily, Store, State, InterfaceIndex, IPAddress,
                InterfaceAlias, LinkLayerAddress
         from MSFT_NetNeighbor
     - name: wmiNamespace
       default: ROOT\StandardCimv2
   
     - name: kMapOfState
       default: |
        {
         "0": "Unreachable",
         "1": "Incomplete",
         "2": "Probe",
         "3": "Delay",
         "4": "Stale",
         "5": "Reachable",
         "6": "Permanent",
         "7": "TBD"
        }
   
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           LET interfaces <=
             SELECT Index, HardwareAddr, IP
             FROM Artifact.Windows.Network.InterfaceAddresses()
   
         - |
           LET arp_cache = SELECT if(condition=AddressFamily=23,
                       then="IPv6",
                     else=if(condition=AddressFamily=2,
                       then="IPv4",
                     else=AddressFamily)) as AddressFamily,
   
                  if(condition=Store=0,
                       then="Persistent",
                     else=if(condition=(Store=1),
                       then="Active",
                     else="?")) as Store,
   
                  get(item=parse_json(data=kMapOfState),
                      member=encode(string=State, type='string')) AS State,
                  InterfaceIndex, IPAddress,
                  InterfaceAlias, LinkLayerAddress
               FROM wmi(query=wmiQuery, namespace=wmiNamespace)
         - |
           SELECT * FROM foreach(
             row=arp_cache,
             query={
                SELECT AddressFamily, Store, State, InterfaceIndex,
                       IP AS LocalAddress, HardwareAddr, IPAddress as RemoteAddress,
                       InterfaceAlias, LinkLayerAddress AS RemoteMACAddress
                FROM interfaces
                WHERE InterfaceIndex = Index
             })

.. raw:: html

   </div></div>


.. |Windows_Network_InterfaceAddressesDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Network_InterfaceAddressesDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Network_InterfaceAddressesDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Network.InterfaceAddresses
**********************************
|Windows_Network_InterfaceAddressesDetails| Network interfaces and relevant metadata.

.. raw:: html

  <div class="collapse" id="Windows_Network_InterfaceAddressesDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Network.InterfaceAddresses
   description: Network interfaces and relevant metadata.
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           LET interface_address =
              SELECT Index, MTU, Name, HardwareAddr, Flags, Addrs
              from interfaces()
   
         - |
           SELECT Index, MTU, Name, HardwareAddr,
              Flags, Addrs.IP as IP, Addrs.Mask as Mask
           FROM flatten(query=interface_address)

.. raw:: html

   </div></div>


.. |Windows_Network_ListeningPortsDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Network_ListeningPortsDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Network_ListeningPortsDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Network.ListeningPorts
******************************
|Windows_Network_ListeningPortsDetails| Processes with listening (bound) network sockets/ports.

.. raw:: html

  <div class="collapse" id="Windows_Network_ListeningPortsDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Network.ListeningPorts
   description: Processes with listening (bound) network sockets/ports.
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           LET process <= SELECT Name, Pid from pslist()
   
         - |
           SELECT * from foreach(
             row={
               SELECT Pid AS PortPid, Laddr.Port AS Port,
                      TypeString as Protocol, FamilyString as Family,
                      Laddr.IP as Address
               FROM netstat() where Status = 'LISTEN'
             },
             query={
               SELECT Pid, Name, Port, Protocol, Family, Address
               FROM process where Pid = PortPid
             })

.. raw:: html

   </div></div>


.. |Windows_Network_NetstatDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Network_NetstatDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Network_NetstatDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Network.Netstat
***********************
|Windows_Network_NetstatDetails| Show information about open sockets. On windows the time when the
socket was first bound is also shown.


.. raw:: html

  <div class="collapse" id="Windows_Network_NetstatDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Network.Netstat
   description: |
     Show information about open sockets. On windows the time when the
     socket was first bound is also shown.
   
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           SELECT Pid, FamilyString as Family,
                  TypeString as Type,
                  Status,
                  Laddr.IP, Laddr.Port,
                  Raddr.IP, Raddr.Port,
                  Timestamp
                  FROM netstat()

.. raw:: html

   </div></div>


.. |Windows_Packs_AutoexecDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Packs_AutoexecDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Packs_AutoexecDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Packs.Autoexec
**********************
|Windows_Packs_AutoexecDetails| Aggregate of executables that will automatically execute on the
target machine. This is an amalgamation of other tables like
services, scheduled_tasks, startup_items and more.


.. raw:: html

  <div class="collapse" id="Windows_Packs_AutoexecDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Packs.Autoexec
   description: |
     Aggregate of executables that will automatically execute on the
     target machine. This is an amalgamation of other tables like
     services, scheduled_tasks, startup_items and more.
   
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           SELECT * from chain(
             q1={
               SELECT Name, Command AS Path, "StartupItems" as Source
               FROM Artifact.Windows.Sys.StartupItems()
             })

.. raw:: html

   </div></div>


.. |Windows_Persistence_PermanentWMIEventsDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Persistence_PermanentWMIEventsDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Persistence_PermanentWMIEventsDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Persistence.PermanentWMIEvents
**************************************
|Windows_Persistence_PermanentWMIEventsDetails| Malware often registers a permanent event listener within WMI. When
the event fires, the WMI system itself will invoke the consumer to
handle the event. The malware does not need to be running at the
time the event fires. Malware can use this mechanism to re-infect
the machine for example.


.. raw:: html

  <div class="collapse" id="Windows_Persistence_PermanentWMIEventsDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Persistence.PermanentWMIEvents
   description: |
      Malware often registers a permanent event listener within WMI. When
      the event fires, the WMI system itself will invoke the consumer to
      handle the event. The malware does not need to be running at the
      time the event fires. Malware can use this mechanism to re-infect
      the machine for example.
   
   parameters:
     - name: namespace
       default: root/subscription
   
   sources:
    - precondition:
        SELECT OS from info() where OS = "windows"
      queries:
      - |
        LET FilterToConsumerBinding = SELECT parse_string_with_regex(
           string=Consumer,
           regex=['((?P<namespace>^[^:]+):)?(?P<Type>.+?)\\.Name="(?P<Name>.+)"']) as Consumer,
             parse_string_with_regex(
           string=Filter,
           regex=['((?P<namespace>^[^:]+):)?(?P<Type>.+?)\\.Name="(?P<Name>.+)"']) as Filter
        FROM wmi(
            query="SELECT * FROM __FilterToConsumerBinding",
            namespace=namespace)
      - |
        SELECT {
          SELECT * FROM wmi(
             query="SELECT * FROM " + Consumer.Type,
             namespace=if(condition=Consumer.namespace,
                 then=Consumer.namespace,
                 else=namespace)) WHERE Name = Consumer.Name
        } AS ConsumerDetails,
        {
          SELECT * FROM wmi(
             query="SELECT * FROM " + Filter.Type,
             namespace=if(condition=Filter.namespace,
                 then=Filter.namespace,
                 else=namespace)) WHERE Name = Filter.Name
        } AS FilterDetails
        FROM FilterToConsumerBinding

.. raw:: html

   </div></div>


.. |Windows_Persistence_PowershellRegistryDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Persistence_PowershellRegistryDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Persistence_PowershellRegistryDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Persistence.PowershellRegistry
**************************************
|Windows_Persistence_PowershellRegistryDetails| A common way of persistence is to install a hook into a user profile
registry hive, using powershell. When the user logs in, the
powershell script downloads a payload and executes it.

This artifact searches the user's profile registry hive for
signatures related to general Powershell execution. We use a yara
signature specifically targeting the user's profile which we extract
using raw NTFS parsing (in case the user is currently logged on and
the registry hive is locked).


.. raw:: html

  <div class="collapse" id="Windows_Persistence_PowershellRegistryDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Persistence.PowershellRegistry
   description: |
     A common way of persistence is to install a hook into a user profile
     registry hive, using powershell. When the user logs in, the
     powershell script downloads a payload and executes it.
   
     This artifact searches the user's profile registry hive for
     signatures related to general Powershell execution. We use a yara
     signature specifically targeting the user's profile which we extract
     using raw NTFS parsing (in case the user is currently logged on and
     the registry hive is locked).
   
   parameters:
     - name: yaraRule
       default: |
         rule PowerShell {
           strings:
             $a = /ActiveXObject.{,500}eval/ wide nocase
   
           condition:
             any of them
         }
   
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           SELECT * from foreach(
           row={
             SELECT Name, Directory as HomeDir from Artifact.Windows.Sys.Users()
             WHERE Directory and Gid
           },
           query={
             SELECT File.FullPath As FullPath,
                    Strings.Offset AS Off,
                    Strings.HexData As Hex,
                    upload(file=File.FullPath, accessor="ntfs") AS Upload
                 FROM yara(
                 files="\\\\.\\" + HomeDir + "\\ntuser.dat",
                 accessor="ntfs",
                 rules=yaraRule, context=50)
           })

.. raw:: html

   </div></div>


.. |Windows_Registry_NTUser_UploadDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Registry_NTUser_UploadDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Registry_NTUser_UploadDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Registry.NTUser.Upload
******************************
|Windows_Registry_NTUser_UploadDetails| This artifact collects all the user's NTUser.dat registry hives.

When a user logs into a windows machine the system creates their own
"profile" which consists of a registry hive mapped into the
HKEY_USERS hive. This hive file is locked as long as the user is
logged in.

This artifact bypasses the locking mechanism by extracting the
registry hives using raw NTFS parsing. We then just upload all hives
to the server.


.. raw:: html

  <div class="collapse" id="Windows_Registry_NTUser_UploadDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Registry.NTUser.Upload
   description: |
     This artifact collects all the user's NTUser.dat registry hives.
   
     When a user logs into a windows machine the system creates their own
     "profile" which consists of a registry hive mapped into the
     HKEY_USERS hive. This hive file is locked as long as the user is
     logged in.
   
     This artifact bypasses the locking mechanism by extracting the
     registry hives using raw NTFS parsing. We then just upload all hives
     to the server.
   
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           LET users = SELECT Name, Directory as HomeDir
               FROM Artifact.Windows.Sys.Users()
               WHERE Directory
   
         - |
           SELECT upload(file="\\\\.\\" + HomeDir + "\\ntuser.dat",
                         accessor="ntfs") as Upload
           FROM users

.. raw:: html

   </div></div>


.. |Windows_Sys_AppcompatShimsDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Sys_AppcompatShimsDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Sys_AppcompatShimsDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Sys.AppcompatShims
**************************
|Windows_Sys_AppcompatShimsDetails| Application Compatibility shims are a way to persist malware. This
table presents the AppCompat Shim information from the registry in a
nice format.


.. raw:: html

  <div class="collapse" id="Windows_Sys_AppcompatShimsDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Sys.AppcompatShims
   description: |
     Application Compatibility shims are a way to persist malware. This
     table presents the AppCompat Shim information from the registry in a
     nice format.
   
   reference: |
     http://files.brucon.org/2015/Tomczak_and_Ballenthin_Shims_for_the_Win.pdf
   
   parameters:
     - name: shimKeys
       default: >-
         HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\*
     - name: customKeys
       default: >-
         HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\*\*
   
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           LET installed_sdb <=
              SELECT Key, Key.Name as SdbGUID, DatabasePath,
                     DatabaseType, DatabaseDescription,
                     -- Convert windows file time to unix epoch.
                     (DatabaseInstallTimeStamp / 10000000) - 11644473600 AS DatabaseInstallTimeStamp
              FROM read_reg_key(
                globs=split(string=shimKeys, sep=",[\\s]*"),
                accessor="reg")
         - |
           LET result = SELECT * from foreach(
             row={
               SELECT regex_replace(
                  source=FullPath,
                  replace="$1",
                  re="^.+\\\\([^\\\\]+)\\\\[^\\\\]+$") as Executable,
                 regex_replace(
                  source=Name,
                  replace="$1",
                  re="(\\{[^}]+\\}).*$") as SdbGUIDRef,
                  Name as ExeName from glob(
                 globs=split(string=customKeys, sep=",[\\s]*"),
                 accessor="reg")
             },
             query={
               SELECT Executable, DatabasePath, DatabaseType,
                      DatabaseDescription, DatabaseInstallTimeStamp, SdbGUID
               FROM installed_sdb
               WHERE SdbGUID = SdbGUIDRef
             })
         - |
           SELECT * from result

.. raw:: html

   </div></div>


.. |Windows_Sys_CertificateAuthoritiesDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Sys_CertificateAuthoritiesDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Sys_CertificateAuthoritiesDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Sys.CertificateAuthorities
**********************************
|Windows_Sys_CertificateAuthoritiesDetails| Certificate Authorities installed in Keychains/ca-bundles.

.. raw:: html

  <div class="collapse" id="Windows_Sys_CertificateAuthoritiesDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Sys.CertificateAuthorities
   description: Certificate Authorities installed in Keychains/ca-bundles.
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           select Store, IsCA, Subject,
                  encode(string=SubjectKeyId, type='hex') AS SubjectKeyId,
                  encode(string=AuthorityKeyId, type='hex') AS AuthorityKeyId,
                  Issuer, KeyUsageString,
                  IsSelfSigned, SHA1, SignatureAlgorithm, PublicKeyAlgorithm, KeyStrength,
                  NotBefore, NotAfter, HexSerialNumber
                  from certificates()

.. raw:: html

   </div></div>


.. |Windows_Sys_DiskInfoDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Sys_DiskInfoDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Sys_DiskInfoDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Sys.DiskInfo
********************
|Windows_Sys_DiskInfoDetails| Retrieve basic information about the physical disks of a system.

.. raw:: html

  <div class="collapse" id="Windows_Sys_DiskInfoDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Sys.DiskInfo
   description: Retrieve basic information about the physical disks of a system.
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           SELECT Partitions,
                  Index as DiskIndex,
                  InterfaceType as Type,
                  PNPDeviceID,
                  DeviceID,
                  Size,
                  Manufacturer,
                  Model,
                  Name,
                  SerialNumber,
                  Description
           FROM wmi(
              query="SELECT * from Win32_DiskDrive",
              namespace="ROOT\\CIMV2")

.. raw:: html

   </div></div>


.. |Windows_Sys_DriversDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Sys_DriversDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Sys_DriversDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Sys.Drivers
*******************
|Windows_Sys_DriversDetails| Details for in-use Windows device drivers. This does not display installed but unused drivers.

.. raw:: html

  <div class="collapse" id="Windows_Sys_DriversDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Sys.Drivers
   description: Details for in-use Windows device drivers. This does not display installed but unused drivers.
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           SELECT * from wmi(
               query="select * from Win32_PnPSignedDriver",
               namespace="ROOT\\CIMV2")

.. raw:: html

   </div></div>


.. |Windows_Sys_FirewallRulesDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Sys_FirewallRulesDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Sys_FirewallRulesDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Sys.FirewallRules
*************************
|Windows_Sys_FirewallRulesDetails| List windows firewall rules.

.. raw:: html

  <div class="collapse" id="Windows_Sys_FirewallRulesDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Sys.FirewallRules
   description: List windows firewall rules.
   reference:
     https://social.technet.microsoft.com/Forums/azure/en-US/aaed9c6a-fb8b-4d43-8b69-9f4e0f619a8c/how-to-check-the-windows-firewall-settings-from-netsh-command?forum=winserverGP
   
   parameters:
     - name: regKey
       default: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\**\FirewallRules\*
   
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           LET rules = SELECT Name as Value,
                  parse_string_with_regex(string=Data,
                    regex=["Action=(?P<Action>[^|]+)",
                           "Active=(?P<Active>[^|]+)",
                           "Dir=(?P<Dir>[^|]+)",
                           "Protocol=(?P<Protocol>[^|]+)",
                           "LPort=(?P<LPort>[^|]+)",
                           "Name=(?P<Name>[^|]+)",
                           "Desc=(?P<Desc>[^|]+)",
                           "App=(?P<App>[^|]+)"]) as Record,
                  Data,
                  FullPath
           FROM glob(globs=regKey, accessor="reg")
   
         - |
           SELECT Value,
                  Record.Action as Action,
                  Record.Name as Name,
                  Record.Desc as Desc,
                  Record.App as App,
                  Record.Action as Action,
                  Record.Dir as Dir,
                  if(condition=Record.Protocol = "6",
                     then="TCP",
                     else=if(condition=Record.Protocol = "17",
                             then="UDP",
                             else=Record.Protocol)) as Protocol,
                  if(condition=Record.LPort = NULL,
                     then="Any",
                     else=Record.LPort) as LPort,
                  Record.Name as Name
           FROM rules

.. raw:: html

   </div></div>


.. |Windows_Sys_InterfacesDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Sys_InterfacesDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Sys_InterfacesDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Sys.Interfaces
**********************
|Windows_Sys_InterfacesDetails| Report information about the systems interfaces. This artifact
simply parses the output from ipconfig /all.


.. raw:: html

  <div class="collapse" id="Windows_Sys_InterfacesDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Sys.Interfaces
   description: |
     Report information about the systems interfaces. This artifact
     simply parses the output from ipconfig /all.
   
   sources:
    - precondition:
        SELECT OS from info() where OS = "windows"
      queries:
      - |
        // Run ipconfig to get all information about interfaces.
        LET ipconfig = SELECT * FROM execve(argv=['ipconfig', '/all'])
      - |
        // This produces a single row per interface.
        LET interfaces = SELECT Name, Data FROM parse_records_with_regex(
           file=ipconfig.Stdout,
           accessor='data',      // This makes the data appear as a file.
           regex='(?s)Ethernet adapter (?P<Name>[^:]+?):\r\n\r\n(?P<Data>.+?)\r\n(\r\n|$)')
      - |
        // Now extract interesting things from each interface definition.
        SELECT Name, parse_string_with_regex(
           string=Data,
           regex=[
             "Description[^:]+: (?P<Description>.+)\r\n",
             "Physical Address[^:]+: (?P<MAC>.+)\r\n",
             "IPv4 Address[^:]+: (?P<IP>[0-9.]+)",
             "Default Gateway[^:]+: (?P<Gateway>.+)\r\n",
             "DNS Servers[^:]+: (?P<DNS>.+)\r\n",
             "DHCP Server[^:]+: (?P<DHCP>.+)\r\n"
           ]
        ) As Details FROM interfaces

.. raw:: html

   </div></div>


.. |Windows_Sys_PhysicalMemoryRangesDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Sys_PhysicalMemoryRangesDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Sys_PhysicalMemoryRangesDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Sys.PhysicalMemoryRanges
********************************
|Windows_Sys_PhysicalMemoryRangesDetails| List Windows physical memory ranges.

.. raw:: html

  <div class="collapse" id="Windows_Sys_PhysicalMemoryRangesDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Sys.PhysicalMemoryRanges
   description: List Windows physical memory ranges.
   reference: |
     https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ns-wdm-_cm_resource_list
   parameters:
     - name: physicalMemoryKey
       default: HKEY_LOCAL_MACHINE\HARDWARE\RESOURCEMAP\System Resources\Physical Memory\.Translated
   
     - name: Profile
       default: |
         {
           "CM_RESOURCE_LIST": [0, {
             "Count": [0, ["uint32"]],
             "List": [4, ["CM_FULL_RESOURCE_DESCRIPTOR"]]
            }],
            "CM_FULL_RESOURCE_DESCRIPTOR": [0, {
              "PartialResourceList": [8, ["CM_PARTIAL_RESOURCE_LIST"]]
            }],
   
            "CM_PARTIAL_RESOURCE_LIST": [0, {
              "Version": [0, ["uint16"]],
              "Revision": [2, ["uint16"]],
              "Count": [4, ["uint32"]],
              "PartialDescriptors": [8, ["Array", {
                 "Target": "CM_PARTIAL_RESOURCE_DESCRIPTOR"
              }]]
            }],
   
            "CM_PARTIAL_RESOURCE_DESCRIPTOR": [20, {
              "Type": [0, ["char"]],
              "ShareDisposition": [1, ["char"]],
              "Flags": [2, ["uint16"]],
              "Start": [4, ["int64"]],
              "Length": [12, ["uint32"]]
            }]
         }
   
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           SELECT Type.AsInteger as Type,
                  format(format="%#0x", args=Start.AsInteger) as Start,
                  format(format="%#0x", args=Length.AsInteger) as Length
           FROM foreach(
             row={
               SELECT Data
                 FROM stat(filename=physicalMemoryKey, accessor='reg')
             },
             query={
               SELECT Type, Start, Length, Data FROM binary_parse(
                 string=Data.value,
                 profile=Profile,
                 target="CM_RESOURCE_LIST",
                 start="List.PartialResourceList.PartialDescriptors")
             })

.. raw:: html

   </div></div>


.. |Windows_Sys_ProgramsDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Sys_ProgramsDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Sys_ProgramsDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Sys.Programs
********************
|Windows_Sys_ProgramsDetails| Represents products as they are installed by Windows Installer. A product generally
correlates to one installation package on Windows. Some fields may be blank as Windows
installation details are left to the discretion of the product author.


.. raw:: html

  <div class="collapse" id="Windows_Sys_ProgramsDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Sys.Programs
   description: |
     Represents products as they are installed by Windows Installer. A product generally
     correlates to one installation package on Windows. Some fields may be blank as Windows
     installation details are left to the discretion of the product author.
   reference: https://github.com/facebook/osquery/blob/master/specs/windows/programs.table
   
   parameters:
     - name: programKeys
       default: >-
         HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*,
         HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
         HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
   
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           SELECT Key.Name as Name,
                  DisplayName,
                  DisplayVersion,
                  InstallLocation,
                  InstallSource,
                  Language,
                  Publisher,
                  UninstallString,
                  InstallDate
           FROM read_reg_key(globs=split(string=programKeys, sep=',[\\s]*'))

.. raw:: html

   </div></div>


.. |Windows_Sys_StartupItemsDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Sys_StartupItemsDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Sys_StartupItemsDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Sys.StartupItems
************************
|Windows_Sys_StartupItemsDetails| Applications that will be started up from the various run key locations.

.. raw:: html

  <div class="collapse" id="Windows_Sys_StartupItemsDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Sys.StartupItems
   description: Applications that will be started up from the various run key locations.
   reference: |
     https://docs.microsoft.com/en-us/windows/desktop/setupapi/run-and-runonce-registry-keys
   parameters:
     - name: runKeyGlobs
       default: >
         HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*\*,
         HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run*\*,
         HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run*\*
         HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*\*,
         HKEY_USERS\*\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run*\*,
         HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run*\*
     - name: startupApprovedGlobs
       default: >
         HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\**,
         HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\**
     - name: startupFolderDirectories
       default: >
         C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/**,
         C:/Users/*/AppData/Roaming/Microsoft/Windows/StartMenu/Programs/Startup/**
   
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           /* We need to search this multiple times so we materialize it
              into a variable (using the <= operator)
            */
           LET approved <=
              SELECT Name as ApprovedName,
                     encode(string=Data, type="hex") as Enabled
              FROM glob(globs=split(
                        string=startupApprovedGlobs, sep="[, ]+"),
                        accessor="reg")
              WHERE Enabled =~ "^0[0-9]0+$"
   
         - |
           LET registry_runners = SELECT Name,
             FullPath, Data.value as Command,
             if(
              condition={
                   SELECT Enabled from approved
                   WHERE Name = ApprovedName
              },
              then="enabled", else="disabled") as Enabled
             FROM glob(
              globs=split(string=runKeyGlobs, sep="[, ]+"),
              accessor="reg")
   
         - |
           LET file_runners = SELECT * FROM foreach(
              row={
                 SELECT Name, FullPath
                 FROM glob(
                    globs=split(string=startupFolderDirectories,
                    sep=",\\s*"))
              }, query={
                 SELECT Name, FullPath, "enable" as Enabled,
                     encode(string=Data, type='utf16') as Command
                 FROM read_file(filenames=FullPath)
              })
   
         - SELECT * from chain(
              first=registry_runners,
              second=file_runners)

.. raw:: html

   </div></div>


.. |Windows_Sys_UsersDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_Sys_UsersDetails" role="button"
     aria-expanded="false" aria-controls="Windows_Sys_UsersDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.Sys.Users
*****************
|Windows_Sys_UsersDetails| List User accounts. We combine two data sources - the output from
the NetUserEnum() call and the list of SIDs in the registry.


.. raw:: html

  <div class="collapse" id="Windows_Sys_UsersDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.Sys.Users
   description: |
     List User accounts. We combine two data sources - the output from
     the NetUserEnum() call and the list of SIDs in the registry.
   
   parameters:
     - name: remoteRegKey
       default: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*
   
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           LET roaming_users <=
              SELECT "" as Uid, "" as Gid,
                  lookupSID(
                    sid=basename(path=Key.FullPath)
                  ) as Name,
                  Key.FullPath as Description,
                  ProfileImagePath as Directory,
                  basename(path=Key.FullPath) as UUID, "roaming" as Type
              FROM read_reg_key(globs=remoteRegKey, accessor="reg")
         - |
           LET local_users <= select User_id as Uid, Primary_group_id as Gid, Name,
                  Comment as Description, {
                    SELECT Directory from roaming_users WHERE User_sid = UUID
                  } as Directory, User_sid as UUID, "local" AS Type
           FROM users()
   
         - |
           SELECT * from chain(
            q1=local_users,
            q2={
              -- Only show users not already shown in the local_users above.
              SELECT * from roaming_users
              where not UUID in local_users.UUID
            })

.. raw:: html

   </div></div>


.. |Windows_System_SVCHostDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_System_SVCHostDetails" role="button"
     aria-expanded="false" aria-controls="Windows_System_SVCHostDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.System.SVCHost
**********************
|Windows_System_SVCHostDetails| Typically a windows system will have many svchost.exe
processes. Sometimes attackers name their processes svchost.exe to
try to hide. Typically svchost.exe is spawned by services.exe.

This artifact lists all the processes named svchost.exe and their
parents if the parent is not also named services.exe.


.. raw:: html

  <div class="collapse" id="Windows_System_SVCHostDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.System.SVCHost
   description: |
     Typically a windows system will have many svchost.exe
     processes. Sometimes attackers name their processes svchost.exe to
     try to hide. Typically svchost.exe is spawned by services.exe.
   
     This artifact lists all the processes named svchost.exe and their
     parents if the parent is not also named services.exe.
   
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'windows'
   
       queries:
         - |
           // Cache the pslist output in memory.
           LET processes <= SELECT * FROM pslist()
   
         - |
           // Get the pids of all procecesses named services.exe
           LET services <= SELECT Pid FROM processes where Name =~ "services.exe"
   
         - |
           // The interesting processes are those which are not spawned by services.exe
           LET suspicious = SELECT Pid As SVCHostPid,
               Ppid As SVCHostPpid,
               Exe as SVCHostExe,
               CommandLine as SVCHostCommandLine
           FROM processes
           WHERE Name =~ "svchost" AND NOT Ppid in services.Pid
   
         - |
           // Now for each such process we display its actual parent.
           SELECT * from foreach(
              row=suspicious,
              query={
                 SELECT SVCHostPid, SVCHostPpid, SVCHostExe,
                        SVCHostCommandLine, Name as ParentName,
                        Exe As ParentExe
                 FROM processes
                 WHERE Pid=SVCHostPpid
             })

.. raw:: html

   </div></div>


.. |Windows_System_UntrustedBinariesDetails| raw:: html

  <a data-toggle="collapse" class='details-opener'
     href="#Windows_System_UntrustedBinariesDetails" role="button"
     aria-expanded="false" aria-controls="Windows_System_UntrustedBinariesDetails">
     <i class="fa fa-lg fa-plus-square-o to_open"></i>
     <i class="fa fa-lg fa-minus-square-o to_close"></i>
  </a>

Windows.System.UntrustedBinaries
********************************
|Windows_System_UntrustedBinariesDetails| Windows runs a number of services and binaries as part of the
operating system. Sometimes malware pretends to run as those well
known names in order to hide itself in plain sight. For example, a
malware service might call itself svchost.exe so it shows up in the
process listing as a benign service.

This artifact checks that the common systems binaries are
signed. If a malware replaces these files or names itself in this
way their signature might not be correct.

Note that unfortunately Microsoft does not sign all their common
binaries so many will not be signed (e.g. conhost.exe).


.. raw:: html

  <div class="collapse" id="Windows_System_UntrustedBinariesDetails">
  <div class="card card-body">
        
.. code-block:: yaml

   name: Windows.System.UntrustedBinaries
   description: |
     Windows runs a number of services and binaries as part of the
     operating system. Sometimes malware pretends to run as those well
     known names in order to hide itself in plain sight. For example, a
     malware service might call itself svchost.exe so it shows up in the
     process listing as a benign service.
   
     This artifact checks that the common systems binaries are
     signed. If a malware replaces these files or names itself in this
     way their signature might not be correct.
   
     Note that unfortunately Microsoft does not sign all their common
     binaries so many will not be signed (e.g. conhost.exe).
   
   parameters:
     - name: processNamesRegex
       description: A regex to select running processes which we consider should be trusted.
       default: (?i)lsass|svchost|conhost|taskmgr|winlogon|wmiprv|dwm|csrss|velociraptor
   
   sources:
     - precondition: |
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           LET binaries = SELECT lowcase(string=Exe) As Binary
             FROM pslist()
             WHERE Exe =~ processNamesRegex
             GROUP BY Binary
   
         - |
           LET auth = SELECT authenticode(filename=Binary) As Authenticode
           FROM binaries
         - |
           SELECT Authenticode.Filename As Filename,
                  Authenticode.IssuerName as Issuer,
                  Authenticode.SubjectName as Subject,
                  Authenticode.Trusted as Trusted from auth

.. raw:: html

   </div></div>

