import easygui as g
import nfqueue

class UI:
    @staticmethod
    def prompt_user( app_name, app_path, app_icon, d_addr, d_port, proto  ):
        title = 'OpenSnitch'
        msg = "%s (%s) wants to connect to %s on %s port %s" % ( \
                app_name,
                app_path,
                d_addr,
                proto.upper(),
                d_port )
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

