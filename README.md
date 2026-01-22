# octodns-domeneshop

## Domeneshop provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets [Domeneshop](https://www.domeneshop.no/).

### Installation

#### Command line

```
pip install octodns-domeneshop
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==1.5.0
octodns-domeneshop==0.0.1
```

### Configuration

```yaml
providers:
  domeneshop:
    class: octodns_domeneshop.DomeneshopProvider
    # API token (required)
    token: env/DOMENESHOP_TOKEN
    # API secret (required)
    secret: env/DOMENESHOP_SECRET
    # Include registrar nameservers as root NS records when dumping (optional)
    # Used if you only use domeneshop for registrar for some domains.
    include_nameservers: false
```

### Credentials

To generate API credentials, visit [this page](https://www.domeneshop.no/admin?view=api) after logging in to the control panel on the Domeneshop website.

See the [Domeneshop API documentation](https://api.domeneshop.no/docs/) for more information.

### Support Information

#### Records

The following record types are supported:

| Record | Support |
|--------|---------|
| A      | ✅      |
| AAAA   | ✅      |
| ALIAS  | ✅      |
| CAA    | ✅      |
| CNAME  | ✅      |
| DS     | ✅      |
| MX     | ✅      |
| NS     | ✅      |
| SRV    | ✅      |
| TLSA   | ✅      |
| TXT    | ✅      |

#### Dynamic

DomeneshopProvider does not support dynamic records.

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.

#### Running Tests

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest
```
