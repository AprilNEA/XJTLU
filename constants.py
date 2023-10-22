import re


class BaseUrl:
    main = "xjtlu.edu.cn"
    core = "core.xjtlu.edu.cn"
    sso = "sso.xjtlu.edu.cn"
    app = "portalapp.xjtlu.edu.cn"

    @classmethod
    def get(cls, name, tls=True):
        return f"{'https' if tls else 'http'}://{getattr(cls, name)}"


class RePattern:
    class Sso:
        csrfPattern = re.compile(
            r'<input type="hidden" name="csrfToken" value="(\d+)"></input>'
        )
        executionPattern = re.compile(r'<input type="hidden" name="execution" value="(\w+)"/>')
        ltPattern = re.compile(r'<input type="hidden" name="lt" value="(\S+)"/>')

    class Core:
        jSessionIDPattern = re.compile(r"JSESSIONID=(\w+);")
        idpPattern = re.compile(
            r'<a class="btn btn-secondary btn-block" title="XJTLU Account" href="(\S+)">XJTLU Account</a>'
        )

        SAMLRequestPattern = re.compile(
            r"""<meta http-equiv="refresh" content="0;URL='(\S+)'">"""
        )

        relayStatePattern = re.compile(
            r'<input type="hidden" name="RelayState" value="(\S+)"/>'
        )
        SAMLResponsePattern = re.compile(
            r'<input type="hidden" name="SAMLResponse" value="(\S+)"/>'
        )

        @classmethod
        def sess_key(cls, base: BaseUrl | str = BaseUrl.core):
            return re.compile(f'{base}","sesskey":"(\w+)","sessiont')

    class Ebridge:
        KeyPattern = re.compile(r'<script>sits_user_timeout = "(\S+)";</script>')
        SIW_LGN_PARAMS = [
            "%.DUM_MESSAGE.MENSYS",
            "%.DUMMY_B.MENSYS",
            "%.DUMMY.MENSYS.1",
            "RUNTIME.DUMMY.MENSYS.1",
            "PARS.DUMMY.MENSYS.1",
            "SSO_OPTION.DUMMY.MENSYS.1",
            "FORM_VERIFICATION_TOKEN.DUMMY.MENSYS.1",
            "BP101.DUMMY_B.MENSYS",
        ]
