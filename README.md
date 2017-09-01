# RavenDB Manager
This simple library helps you to manage your [RavenDB](https://ravendb.net/) servers. It has been tested with RavenDB 3.0 and 3.5.

You will need to provide an API key. Some commands will require `Admin` privileges on the `<system>` database. The API key feature is only available in commercial licenced versions of RavenDB.

## Usage

### Connect to Server
```ruby
require 'ravendb-manager'
manager = RavenDBManager.create("http://raven.server:8088", "apikey/raBreMBH9xv1aanDPZGx23Kv6ow7mrd")
```

### Get Server Version
Will return the build and product version of the server.
```ruby
manager.version
=> {"ProductVersion"=>"d3c9854", "BuildVersion"=>30172}
```

### List Databases
Will list all databases on the server.
```ruby
manager.list_databases
=> ["DB1", "DB2"]
```

### List Filesystems
Will list all filesystems on the server.
```ruby
manager.list_filesystems
=> ["Filesystem1", "Filesystem2"]
```

### Get Alerts
Gets RavenDB alerts from a database.
```ruby
# Get Alerts of System Database
manager.alerts
=> [{"Title"=>"Index disk 'C:\\' has 2697MB (4%) of free space. Indexing will be disabled when it reaches 2048MB.", "CreatedAt"=>"2017-04-18T14:35:25.1926262Z", "Observed"=>false, "LastDismissedAt"=>nil, "Message"=>nil, "AlertLevel"=>"Warning", "Exception"=>nil, "UniqueKey"=>"Free space warning (index)"}]

# Get Alerts of a specific database
manager.alerts('DB1')
=> []
```

### Create Database
Creates a new database.
```ruby
manager.create_database("DB3")

# Use Voron as storage backend
manager.create_database("DB3", true)
```

### Create Filesystem
Creates a new filesystem.
```ruby
manager.create_filesystem("Filesystem3")
```

### Store Document
Stores a document. Setting metadata is not (yet) supported.
```ruby
manager.put_document("DB1", "document1", {'Name' => 'Ivan Vorpatril', 'Age' => 35})
=> "document1"
```

### Read Document
Reads a document. Will return `nil` if key is not found.
```ruby
manager.get_document("DB1", "document1")
=> {"Name"=>"Ivan Vorpatril", "Age"=>35}

manager.get_document("DB1", "does_not_exist")
=> nil
```

### Compact Database
Starts compaction of a database. This process runs asynchronously. You have to check the result with the returned OperationId.

**Important**: Database will be **offline** during the compact process
```ruby
opid = manager.compact_database("DB1")
=> 8
manager.get_operation_status(opid)
=> {"Completed"=>true, "Faulted"=>false, "State"=>nil}
```

### Get Database Indexing Status
```ruby
manager.get_indexing_status('DB1')
=> "Indexing"
```

### Get Database Statistics
```ruby
manager.database_statistics("DB1")
=> {"StorageEngine"=>"Esent", "LastDocEtag"=>"01000000 [...]
```

### Get Server Statistics
```ruby
manager.server_statistics
=> {"ServerName"=>nil, "TotalNumberOfReques [...]
```

### Create new API Key
Create a new API key. If an API key with the same name already exists it will be replaced. Returns the newly generated API key.
```ruby
manager.create_api_key('apikey')
=> "apikey/raBreMBH9xv1aanDPZGx23Kv6ow7mrd"
```

### List API Keys
Returns a `Hash` with all API keys.
```ruby
manager.list_api_keys
=> {"apikey"=>{:databases=>[{"Admin"=>true, "TenantId"=>"*", "ReadOnly"=>false}, {"Admin"=>true, "TenantId"=>"<system>", "ReadOnly"=>false}], :secret=>"raBreMBH9xv1aanDPZGx23Kv6ow7mrd"}}
```

### Add Database Permission to API Key
Adds permissions for a database to an API key.

```ruby
# Add read and write permission
manager.add_db_to_api_key('apikey', 'DB1')

# Add admin permission
manager.add_db_to_api_key('apikey', 'DB1', true, false)

# Add read only permission
manager.add_db_to_api_key('apikey', 'DB1', false, true)
```