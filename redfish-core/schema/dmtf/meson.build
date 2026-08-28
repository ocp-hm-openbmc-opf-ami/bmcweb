dmtf_schema_opt = get_option('bmcweb-install-dmtf-schema')

if dmtf_schema_opt == 'enabled'
    install_subdir(
        'installed',
        install_dir: 'share/www/redfish/v1/schema',
        strip_directory: true,
        follow_symlinks: true,
    )
endif

if dmtf_schema_opt != 'disabled'
    install_subdir(
        'json-schema-installed',
        install_dir: 'share/www/redfish/v1/JsonSchemas',
        strip_directory: true,
        follow_symlinks: true,
    )
endif
