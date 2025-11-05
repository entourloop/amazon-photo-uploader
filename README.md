# Amazon Photos uploader

This tool, written in Rust, implements enough of the Amazon Photos API to perform the following operations:
1. Create an album or get a reference to an existing one, proceeding by name.
2. Upload the contents of a directory to an Amazon Photos instance, note down all the pictures' IDs.
3. Add all these pictures to the album.

## Configuration

### Initial Setup

To create your configuration file for the first time, use the `config_setup.py` script:

1. Open Amazon Photos in your web browser and log in
2. Open Developer Tools (F12 or Right-click → Inspect)
3. Go to the Console tab and run:
   ```javascript
   document.cookie
   ```
4. Copy the entire cookie string
5. Run the setup script:
   ```bash
   python3 config_setup.py 'session-id=123; x-acbfr=abc; ...'
   ```

The script will:
- Automatically detect your country from the cookie names
- Create the configuration file with default values
- Display the configuration file location
- Provide instructions for updating the zone if needed

### Configuration File Location

The configuration file is stored in:
- **macOS**: `~/Library/Application Support/amzn_photos_uploader/config.toml`
- **Linux**: `~/.config/amzn_photos_uploader/config.toml`
- **Windows**: `%APPDATA%\amzn_photos_uploader\config.toml`

### Updating Your Configuration

To update your cookies (e.g., after session expiration), use the `config_update.py` script:

```bash
python3 config_update.py 'session-id=123; x-acbfr=abc; ...'
```

This will update the cookie values while preserving your other settings (country, zone, user agent).

### Finding Your Zone

If photo uploads fail, you may need to update the `zone` parameter:

1. Open Amazon Photos in your browser
2. Open Developer Tools → Network tab
3. Upload a photo through the web interface
4. Look for a request to: `https://content-XX.drive.amazonaws.com/v2/upload`
5. Note the `XX` value (e.g., `eu`, `na`, `fe`)
6. Edit your config file and update: `zone = "XX"`