import random
import asyncio

import aiohttp
from bs4 import BeautifulSoup as bs

from constants import BaseUrl, RePattern
from utils import get_ua, parse_code


def sso_login_required(func):
    async def wrapper(self, *args, **kwargs):
        if not self.is_sso_login:
            await self.sso_login()
        return await func(self, *args, **kwargs)

    return wrapper


class AuthEngine:
    def __init__(
            self, username: str, password=None, session: aiohttp.ClientSession = None
    ):
        if session:
            self._new_session = False
            ua = session.headers.getone("User-Agent")
            if not ua:
                session.headers.add("User-Agent", get_ua())
            self.session = session
        else:
            self._new_session = True
            self.session = aiohttp.ClientSession(headers={"User-Agent": get_ua()})

        self.username = username
        self.password = password

        self.is_sso_login = False
        self.is_onestop_login = False

    async def _close_session(self):
        if not self.session.closed:
            await self.session.close()

    def __del__(self):
        if self._new_session:
            try:
                loop = asyncio.get_event_loop()
                asyncio.create_task(self._close_session())
            except RuntimeError:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(self._close_session())

    async def _sso_login(self):
        async with self.session.get(f"{BaseUrl.get('sso')}/login") as response:
            text = await response.text()
            csrfToken = RePattern.Sso.csrfPattern.findall(text)[0]
            lt = RePattern.Sso.ltPattern.findall(text)[0]
            execution = RePattern.Sso.executionPattern.findall(text)[0]
        async with self.session.post(
                url=f"{BaseUrl.get('sso')}/login",
                data={
                    "eid": "esc",
                    "isShowRandomCode": "0",
                    "keyCacheCode": f"{lt}_KEY",
                    "lt": lt,
                    "execution": execution,
                    "_eventId": "submit",
                    "authType": "pwd",
                    "cert": "",
                    "csrfToken": csrfToken,
                    "username": self.username,
                    "password": self.password,
                    "adPasswd": "",
                    "ldapPasswd": "",
                    "otpCode": "",
                    "smsCode": "",
                    "randomCode": "",
                },
                allow_redirects=False,
        ) as response:
            if response.status == 302:
                return True
            else:
                return False

    async def sso_login(self):
        if not self.is_sso_login:
            await self._sso_login()

    async def _auth_engine(self, _type="saml2", **kwargs):
        """
        Standardized certified calibration
        :param _type: SAML2 OAuth2
        :param kwargs:
        :return:
        """
        await self.session.get(
            url=f"{BaseUrl.get('sso')}/AuthnEngine", allow_redirects=False, **kwargs
        )
        await self.session.get(
            url=f"{BaseUrl.get('sso')}/login", allow_redirects=False, **kwargs
        )
        await self.session.get(
            url=f"{BaseUrl.get('sso')}/Authn/Credential",
            allow_redirects=False,
            **kwargs,
        )
        if _type == "saml2":
            async with self.session.get(
                    url=f"{BaseUrl.get('sso')}/profile/SAML2/Unsolicited/SSO",
                    allow_redirects=False,
                    **kwargs,
            ) as response:
                text = await response.text()
            return text
        elif _type == "oauth2":
            async with self.session.get(
                    url=f"{BaseUrl.get('sso')}/profile/oauth2/authorize",
                    allow_redirects=False,
                    **kwargs,
            ) as response:
                return response.headers.getone("Location")

    async def _core_login(self, core_base="core.xjtlu.edu.cn"):
        """
        Login to Core by jumping to SSO
        For archived Core such as core-archive22-23.xjtlu.edu.
        These no longer exist in the list of SSO Apps, so you can't log in directly through the APP.
        """
        # Fetch Cookie: MoodleSessionlearningmall=ffffff
        await self.session.get(url=f"https://{core_base}/", allow_redirects=False)

        await self.session.get(
            url=f"https://{core_base}/login/index.php", allow_redirects=False
        )
        async with self.session.get(
                f"https://{core_base}/local/login/index.php", allow_redirects=False
        ) as response:
            idpUrl = RePattern.Core.idpPattern.findall(await response.text())[0].replace("amp;", "")
        async with self.session.get(url=idpUrl, allow_redirects=False) as response:
            samlUrl = response.headers.getone("Location")
        async with await self.session.get(
                url=samlUrl, allow_redirects=False
        ) as response:
            nextUrl = response.headers.getone("Location")
        async with self.session.get(url=nextUrl, allow_redirects=False) as response:
            if (
                    response.headers.getone("Location")
                    != f"{BaseUrl.get('sso')}:443/AuthnEngine"
            ):
                print("Error", response.headers.getone("Location"))
        text = await self._auth_engine(headers={"Referer": f"https://{core_base}/"})
        ReplyState = RePattern.Core.relayStatePattern.findall(text)[0]
        SAMLResponse = RePattern.Core.SAMLResponsePattern.findall(text)[0]
        async with self.session.post(
                url=f"https://{core_base}/auth/saml2/sp/saml2-acs.php/{core_base}",
                data={"ReplyState": ReplyState, "SAMLResponse": SAMLResponse},
                allow_redirects=False,
        ) as response:
            nextUrl = response.headers.getone("Location")
        await self.session.get(url=nextUrl, allow_redirects=False)
        async with self.session.get(url=f"https://{core_base}") as response:
            self.sessKey = RePattern.Core.sess_key(core_base).findall(await response.text())[0]
        return self.sessKey

    @sso_login_required
    async def core_login(self, core_base="core.xjtlu.edu.cn"):
        """
        The whole login process in learning mall
        """
        if core_base in ["core.xjtlu.edu.cn"]:
            await self._core_login(core_base)

    async def ebridge_login(self):
        async with self.session.get(
                url="https://ebridge.xjtlu.edu.cn/urd/sits.urd/run/siw_lgn"
        ) as response:
            text = await response.text()
        soup = bs(text, "html.parser")
        siw_login_data = {}
        for param in RePattern.Ebridge.SIW_LGN_PARAMS:
            siw_login_data[param] = soup.find("input", attrs={"name": param})["value"]

        siw_login_data["SCREEN_WIDTH.DUMMY.MENSYS.1"] = 1920
        siw_login_data["SCREEN_HEIGHT.DUMMY.MENSYS.1"] = 1080
        siw_login_data["MUA_CODE.DUMMY.MENSYS.1"] = self.username
        siw_login_data["PASSWORD.DUMMY.MENSYS.1"] = self.password

        async with self.session.post(
                url="https://ebridge.xjtlu.edu.cn/urd/sits.urd/run/SIW_LGN",
                data=siw_login_data,
        ) as response:
            text = await response.text()
        soup = bs(text, "html.parser")
        try:
            redirect_url = soup.find("input", attrs={"name": "HREF.DUMMY.MENSYS.1"})[
                "value"
            ]
        except TypeError:
            print("User password error")
            exit(1)

        async with self.session.get(
                url=f"https://ebridge.xjtlu.edu.cn/urd/sits.urd/run/{redirect_url}",
        ) as response:
            text = await response.text()
        soup = bs(text, "html.parser")
        self.tb_url = soup.find("a", attrs={"id": "PRS_STU_TB"}).get("href")

    @sso_login_required
    async def hive_login(self):
        """
        Dormitory Management System Login
        """
        # async with self.session.get(
        #     url="http://hive.xjtlu.edu.cn/hive-api/client/student/info"
        # ) as response:
        #     login_url = (await response.json())["result"]
        async with self.session.get(
                url=f"{BaseUrl.get('sso')}/profile/oauth2/authorize?client_id=h2i5V3EJ4&response_type=code&redirect_uri=http%3A%2F%2Fhive.xjtlu.edu.cn%2Fpc",
                allow_redirects=False,
        ) as response:
            authn_key = response.cookies.get("_idp_authn_lc_key")
            print(authn_key)
        auth_url = (
            await self._auth_engine(
                "oauth2", headers={"Referer": "http://hive.xjtlu.edu.cn/"}
            )
        ).replace("pc?code", "pc/?code")
        code = parse_code(auth_url)
        await self.session.get(
            auth_url,
        )
        async with self.session.post(
                url=f"http://hive.xjtlu.edu.cn/hive-api/client/auth/login?code={code}=http://hive.xjtlu.edu.cn/pc/pages/student-party/index"
        ) as response:
            token = (await response.json())["result"]["token"]
        return token

    async def _onestop_sso_login(self):
        await self.session.get(
            url=f"{BaseUrl.get('sso')}/profile/oauth2/authorize?client_id=CWt5VdrSAE&redirect_uri=http%3A%2F%2Fstudentonestop.xjtlu.edu.cn%2FSsoLogin&response_type=code",
            allow_redirects=False,
        )
        await self.session.get(
            f"{BaseUrl.get('sso')}:443/AuthnEngine", allow_redirects=False
        )
        async with self.session.get(
                url=f"{BaseUrl.get('sso')}/profile/oauth2/authorize",
                allow_redirects=False,
        ) as response:
            nextUrl = response.headers.getone("Location")
        await self.session.get(nextUrl)

    async def onestop_login(self):
        if not self.is_onestop_login:
            await self._onestop_sso_login()
            self.is_onestop_login = True

    @sso_login_required
    async def ams_login(self):
        await self.session.get(
            url=f"{BaseUrl.get('sso')}/profile/oauth2/authorize?client_id=C8Ll6TVjOl&redirect_uri=https://ams.xjtlu.edu.cn/xjtlu/sso/toAutoRedirect&response_type=code",
            allow_redirects=False,
        )
        nextUrl = await self._auth_engine(
            "oauth2", headers={"Referer": "https://ams.xjtlu.edu.cn/"}
        )
        await self.session.get(nextUrl, allow_redirects=False)
        nextUrl = nextUrl.replace("xjtlu/sso/toA", "studentpc/a")
        await self.session.get(nextUrl, allow_redirects=False)
        nextUrl = nextUrl.replace("studentpc", "xjtlu/sso").replace(
            "autoRedirect", "autoRedirectByCode"
        )
        await self.session.get(nextUrl, allow_redirects=False)
        await self.session.get(
            "https://ams.xjtlu.edu.cn/xjtlu/sso/iam/login"
        )
        await self.session.get(
            url=f"{BaseUrl.get('sso')}/profile/oauth2/authorize?client_id=C8Ll6TVjOl&redirect_uri=https://ams.xjtlu.edu.cn/xjtlu/sso/mobile/pc/callback&response_type=code",
            allow_redirects=False,
        )
        await self.session.get(
            f"{BaseUrl.get('sso')}:443/AuthnEngine", allow_redirects=False
        )
        async with self.session.get(
                url=f"{BaseUrl.get('sso')}/profile/oauth2/authorize",
                allow_redirects=False,
        ) as response:
            nextUrl = response.headers.getone("Location")
        code = parse_code(nextUrl)

        async with self.session.get(nextUrl, allow_redirects=False) as response:
            nextUrl = response.headers.getone("Location")
        async with self.session.get(
                f"https://ams.xjtlu.edu.cn/xjtlu/sso/login?code={code}"
        ) as response:
            data = await response.json()
            token = data["data"]["token"]
        return token

    @sso_login_required
    async def ejourney_login(self):
        async with self.session.get(
                url=f"{BaseUrl.get('sso')}/selfService/queryUserAppsProfile?ramdom={random.random()}"
        ) as resp:
            resp = await resp.json()
            items = resp["items"]
            for item in items:
                if item["appName"] == "e-Journey":
                    appId = item["appId"]
                    userId = item["userId"]
                    break
            if not appId:
                raise Exception("e-Journey not found")
        await self.session.get(
            url=f"{BaseUrl.get('sso')}/selfService/getDefaultAccount?resId={appId}"
        )
        await self.session.get(
            url=f"{BaseUrl.get('sso')}/selfService/getAccountLoginParam?accountId={userId}"
        )
        await self.session.get(
            f"{BaseUrl.get('sso')}/applogin/forward/{userId}", allow_redirects=False
        )
        await self.session.get("https://ejourney.xjtlu.edu.cn/", allow_redirects=False)
        async with self.session.get(
                url="https://ejourney.xjtlu.edu.cn/xjtlu/sso/iam/autoRedirect",
                allow_redirects=False,
        ) as resp:
            location = (await resp.json())["data"]
        await self.session.get(
            location, allow_redirects=False
        )
        await self.session.get(
            f"{BaseUrl.get('sso')}/AuthnEngine", allow_redirects=False
        )
        await self.session.get(f"{BaseUrl.get('sso')}/login", allow_redirects=False)
        await self.session.get(
            f"{BaseUrl.get('sso')}/Authn/Credential", allow_redirects=False
        )
        async with self.session.get(
                url=f"{BaseUrl.get('sso')}/profile/oauth2/authorize",
                allow_redirects=False,
        ) as resp:
            location = resp.headers.get("Location")
        await self.session.get(location)
        async with self.session.get(location, allow_redirects=False) as resp:
            location = resp.headers.get("Location")
        await self.session.get(
            url=f"https://ejourney.xjtlu.edu.cn/xjtlu/sso/autoRedirectByCode?code={location[53:]}",
            allow_redirects=False,
        )
        async with self.session.get(
                "https://ejourney.xjtlu.edu.cn/xjtlu/app/sso/iam/login?type=1"
        ) as resp:
            location = (await resp.json())["data"]
        await self.session.get(location, allow_redirects=False)
        await self.session.get(
            f"{BaseUrl.get('sso')}/AuthnEngine", allow_redirects=False
        )
        async with self.session.get(
                url=f"{BaseUrl.get('sso')}/profile/oauth2/authorize",
                allow_redirects=False,
        ) as resp:
            location = resp.headers.get("Location").replace("http:/", "https:/")
        async with self.session.get(location, allow_redirects=False) as resp:
            location = (
                resp.headers.get("Location")
                .replace("http:/", "https:/")
                .replace(".cn/stu/#/?code", ".cn/xjtlu/app/sso/login?code")
            )
        async with self.session.get(location, allow_redirects=False) as resp:
            return (await resp.json()).get("data", {}).get("token", None)
