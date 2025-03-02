The Auth0 FastAPI SDK is a library for implementing user authentication in FastAPI applications.

![Release](https://img.shields.io/pypi/v/auth0-python)
[![Codecov](https://img.shields.io/codecov/c/github/auth0/auth0-python)](https://codecov.io/gh/auth0/auth0-python)
![Downloads](https://img.shields.io/pypi/dw/auth0-python)
[![License](https://img.shields.io/:license-MIT-blue.svg?style=flat)](https://opensource.org/licenses/MIT)
[![CircleCI](https://img.shields.io/circleci/build/github/auth0/auth0-python)](https://circleci.com/gh/auth0/auth0-python)

<div>
📚 <a href="#documentation">Documentation</a> - 🚀 <a href="#getting-started">Getting started</a> - 💻 <a href="#api-reference">API reference</a> - 💬 <a href="#feedback">Feedback</a>
</div>


## Documentation
- [Docs site](https://www.auth0.com/docs) - explore our docs site and learn more about Auth0.


## Getting Started

## Installation

```bash
pip install git+https://github.com/kishore7snehil/fastapi-python.git
```

## Running Tests

1. **Install Dependencies**

   Use [Poetry](https://python-poetry.org/) to install the required dependencies:

   ```sh
   $ poetry install
   ```

2. **Run the tests**

   ```sh
   $ poetry run pytest tests
   ```

## Usage

Create a .env file with the following deatils:

```
AUTH0_DOMAIN='<>'
AUTH0_CLIENT_ID='<>'
AUTH0_CLIENT_SECRET='<>'
AUTH0_REDIRECT_URI='<>'
AUTH0_SECRET_KEY='ALongRandomlyGeneratedString'
AUTH0_APP_BASE_URL='<>'
```

Create a python script for accessing the routes, link and tool token example:

```python
from dotenv import find_dotenv, load_dotenv

from fastapi import FastAPI
import uvicorn

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)


# Create user's FastAPI app
app = FastAPI()

# Create auth client with the user's app
auth_client = Auth(app=app, store="<store_name>")


# Start server as the user wants
if __name__ == "__main__":
    import threading
    server_thread = threading.Thread(
        target=uvicorn.run,
        args=(app,),
        kwargs={"host": "0.0.0.0", "port": 3000}
    )
    server_thread.start()
```

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please read the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/auth0-server-js/blob/main/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](./CONTRIBUTING.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/auth0-server-js/issues).

## Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/responsible-disclosure-policy) details the procedure for disclosing security issues.

## What is Auth0?

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_dark_mode.png" width="150">
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
    <img alt="Auth0 Logo" src="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
  </picture>
</p>
<p align="center">
  Auth0 is an easy to implement, adaptable authentication and authorization platform. To learn more checkout <a href="https://auth0.com/why-auth0">Why Auth0?</a>
</p>
<p align="center">
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/auth0-server-js/blob/main/packages/auth0-fastify/LICENSE"> LICENSE</a> file for more info.
</p>