# azure-activation-service
Auto Activate Azure Roles

The tool works as a companion to the MSRA Intern's Tool.

```bash
# In a bash shell that has the Azure CLI env set up
aas list-roles  # refresh role list
aas import-config  # import auto-renew config from MSRA Intern's Tool
ass auto-activate  # auto activate roles
ass generate-service  # generate user service
systemctl --user enable azure-pim-activator  # enable user service
loginctl enable-linger $USER  # to keep user service active
```

The tool reads and stores everything in `$AZURE_CONFIG_DIR`, so if you are working with multiple users you can do the above operations with different `$AZURE_CONFIG_DIR`.
