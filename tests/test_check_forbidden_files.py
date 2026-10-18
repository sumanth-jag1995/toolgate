from scripts.check_forbidden_files import find_forbidden


def test_flags_secret_files():
    paths = [
        ".env",
        "infra/a.pem",
        "x/id.key",
        "infra/terraform/terraform.tfstate",
        "infra/terraform/terraform.tfstate.backup",
        "prod.tfvars",
    ]
    assert find_forbidden(paths) == paths


def test_allows_examples_and_code():
    assert (
        find_forbidden(
            [
                ".env.example",
                "prod.tfvars.example",
                "src/keys.py",
                "infra/keycloak/toolgate-realm.template.json",
            ]
        )
        == []
    )
