import easygui as g
import nfqueue

class UI:
    @staticmethod
    def prompt_user( c ):
        title = 'OpenSnitch'
        msg = "%s (%s) wants to connect to %s on %s port %s (%s)" % ( \
                c.app.name,
                c.app_path,
                c.hostname,
                c.proto.upper(),
                c.dst_port,
                c.service )
        choices = [ 'Allow Once',
                    'Allow Forever',
                    'Allow All',
                    'Deny Once',
                    'Deny Forever',
                    'Deny All' ]

        idx = g.indexbox(msg, title, choices)

        results = [ \
            ( nfqueue.NF_ACCEPT, False ),
            ( nfqueue.NF_ACCEPT, False ),
            ( nfqueue.NF_ACCEPT, True ),
            ( nfqueue.NF_DROP, False ),
            ( nfqueue.NF_DROP, False ),
            ( nfqueue.NF_DROP, True )
        ]
       
        return results[idx]

