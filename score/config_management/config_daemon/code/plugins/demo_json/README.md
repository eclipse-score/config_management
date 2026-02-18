# Demo JSON plugin

This plugin is intended as an example plugin for ConfigDaemon.

## What it does

- Reads a JSON file from `etc/demo_parameters.json` (relative to `/opt/ConfigDaemon/`).
- Inserts the contained parameter sets / parameters into the ConfigDaemon data model.
- Marks each loaded parameter set as `kQualified` and `calibratable=true`.

## JSON schema

```json
{
	"parameterSets": {
		"DemoSet": {
			"parameters": {
				"ParamA": { "initValue": 123 },
				"ParamC": { "initValue": true }
			}
		}
	}
}
```

`initValue` can be any JSON value (number/bool/null/object/list).

## Manual test

 - Change `/opt/ConfigDaemon/etc/logging.json` to enable debug logging.
 - Move `etc/demo_parameters.json` to `/opt/ConfigDaemon/etc/`
 - Restart ConfigDaemon.
 - Verify via the ConfigDaemon APIs/logs that the parameters exist in the data model (e.g., DLT logs show the parameters are inserted).
