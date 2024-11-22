# Azure Activation Service

Auto Activate Azure Roles!

The tool works as a companion to the [MSRA Intern's Tool](https://github.com/JeffreyXiang/MSRA-Intern-s-Toolkit). Many thanks for jianfeng's great project.

The tool aims to produce a linux user-space service that runs periodically to activate Azure roles so that you don't need to keep your VSCode open.

## Installation

```bash
pip install azure-activation-service
```

## Usage

```bash
# In a bash shell that has the Azure CLI env set up
aas list-roles  # refresh role list
aas import-config  # import auto-renew config from MSRA Intern's Tool
ass auto-activate  # auto activate roles
ass generate-service  # generate user service
systemctl --user enable azure-pim-activator  # enable user service
loginctl enable-linger $USER  # to keep user service active
```

The tool reads and stores everything in `$AZURE_CONFIG_DIR`, so if you are working with multiple users you can do the above operations with different `$AZURE_CONFIG_DIR` and set a different service name when running `ass generate-service [another-name]`.
