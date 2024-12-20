# Private Credentials Demo

This folder contains a simple demo website and server which are designed to demonstrate how to use our credentials library in a concrete setting.

Features:
* Server issues signed credentials to people "registering" with their personal data
* Credentials can be stored in your wallet
* "Anonymous Login" presentation allows simply demonstrating that you have a non-expired credential
* "Anonymous Poll" presentation allows people matching certain criteria to vote in a poll. Nullifiers ensure that a single credential only allows you to vote once.
* For easier testing, users can either use their actual wallet or a mock wallet that is created on the fly by the web page.

Note: The only wallet compatible with Private Credentials is currently [an unreleased version of Pallad](https://github.com/palladians/pallad/pull/231), which is confirmed to work well with this example app, but still in review.

The server is a plain Node.js server located in `/api-server`. The web app is contained in `/src`.
