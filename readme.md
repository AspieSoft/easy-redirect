# Easy Redirect API

[![donation link](https://img.shields.io/badge/buy%20me%20a%20coffee-paypal-blue)](https://paypal.me/shaynejrtaylor?country.x=US&locale.x=en_US)

A simple hosted api for basic subdomain redirects.

## Installation

```shell script
git clone https://github.com/AspieSoft/easy-redirect
```

## Setup

### config.json

```json
{
  "domain": "redirects.example.com",
  "verifyPrefix": "example_com_api_verify"
}
```

### email.json

Note: Currently only compatable with gmail.

```json
{
  "email": "api.example@gmail.com",
  "passwd": "MyAppPassword",
  "name": "Example API <no-reply@example.com>"
}

```
