def migrate(cr, version):
    """The consent and success pages used to be in the noupdate data file.
    On upgrade Odoo skips records whose XMLID is flagged noupdate, even when
    they now come from a regular file. The consent form would then stay
    without a CSRF token while the controller requires one. The flag is
    cleared before the views are reloaded."""
    cr.execute(
        """
        UPDATE ir_model_data
           SET noupdate = false
         WHERE module = 'dub_oauth2_provider'
           AND name IN ('consent_page', 'oauth2_success_page')
        """
    )
