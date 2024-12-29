# Amazon Photos uploader

This tool, written in Rust, implements enough of the Amazon Photos API to perform the following operations:
1. Create an album or get a reference to an existing one, proceeding by name.
2. Upload the contents of a directory to an Amazon Photos instance, note down all the pictures' IDs.
3. Add all these pictures to the album.

## Configuration file

A configuration file needs to be added (it's in `~/Library/Application\ Support/amzn_photos_uploader` on macOS). It holds all geographic and cookie information (enable developer mode in a logged-in browser session and copy the names found in the configuration file).