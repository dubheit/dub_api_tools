def migrate(cr, version):
    """Le pagine di consenso e di successo erano nel file noupdate: all'upgrade
    Odoo salta i record con noupdate sull'XMLID anche se ora arrivano da un file
    normale, e il modulo di consenso resterebbe senza token CSRF mentre il
    controller lo pretende. Si toglie il flag prima che le viste vengano
    ricaricate."""
    cr.execute(
        """
        UPDATE ir_model_data
           SET noupdate = false
         WHERE module = 'dub_oauth2_provider'
           AND name IN ('consent_page', 'oauth2_success_page')
        """
    )
