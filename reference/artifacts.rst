This page displays information about the Velociraptor built in
artifacts. There are 34 artifacts in total. Use the navigation menu
to the right to quickly skip to the right artifact
definition. Definitions may be expanded to view the VQL source.

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
                SELECT Source, dict() as Mtime, dict() as Ctime,
                  dict() as Atime, Type,
                  dict() as Record, Arch, URL, Name from scope()
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
                  Record.InstalledSize as InstalledSize,
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
           SELECT * from split_records(
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
               SELECT ut_type, ut_id, ut_host as Host,
                      ut_user as User,
                     timestamp(epoch=ut_tv.tv_sec) as login_time
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
               FROM netstat()
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
              "Length": [12, ["int32"]]
            }]
         }
   
   sources:
     - precondition:
         SELECT OS From info() where OS = 'windows'
       queries:
         - |
           SELECT Type,
                  format(format="%#0x", args=Start.AsInteger) as Start,
                  format(format="%#0x", args=Length.AsInteger) as Length
           FROM foreach(
             row={
               SELECT Data
                 FROM stat(filename=physicalMemoryKey, accessor='reg')
             },
             query={
               SELECT * FROM binary_parse(
                 string=Data,
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
                  ProfileImagePath.value as Directory,
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

