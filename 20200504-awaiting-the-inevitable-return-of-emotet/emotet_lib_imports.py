#Run with currentAddress == emotet_get_lib function.
#@author Hornetsecurity Security Lab
#@category Emotet
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.data import DataType
from ghidra.program.model.data import DataTypeManager
from ghidra.program.model.data import Enum
from ghidra.program.model.data import EnumDataType

dll_names = ["aclui.dll", "activeds.dll", "admparse.dll", "adsldpc.dll", "advapi32.dll", "advpack.dll", "api-ms-win-core-console-l1-1-0.dll", "api-ms-win-core-datetime-l1-1-0.dll", "api-ms-win-core-debug-l1-1-0.dll", "api-ms-win-core-delayload-l1-1-0.dll", "api-ms-win-core-errorhandling-l1-1-0.dll", "api-ms-win-core-fibers-l1-1-0.dll", "api-ms-win-core-file-l1-1-0.dll", "api-ms-win-core-handle-l1-1-0.dll", "api-ms-win-core-heap-l1-1-0.dll", "api-ms-win-core-interlocked-l1-1-0.dll", "api-ms-win-core-io-l1-1-0.dll", "api-ms-win-core-libraryloader-l1-1-0.dll", "api-ms-win-core-localization-l1-1-0.dll", "api-ms-win-core-localregistry-l1-1-0.dll", "api-ms-win-core-memory-l1-1-0.dll", "api-ms-win-core-misc-l1-1-0.dll", "api-ms-win-core-namedpipe-l1-1-0.dll", "api-ms-win-core-processenvironment-l1-1-0.dll", "api-ms-win-core-processthreads-l1-1-0.dll", "api-ms-win-core-profile-l1-1-0.dll", "api-ms-win-core-rtlsupport-l1-1-0.dll", "api-ms-win-core-string-l1-1-0.dll", "api-ms-win-core-synch-l1-1-0.dll", "api-ms-win-core-sysinfo-l1-1-0.dll", "api-ms-win-core-threadpool-l1-1-0.dll", "api-ms-win-core-util-l1-1-0.dll", "api-ms-win-security-base-l1-1-0.dll", "api-ms-win-security-lsalookup-l1-1-0.dll", "api-ms-win-security-sddl-l1-1-0.dll", "api-ms-win-service-core-l1-1-0.dll", "api-ms-win-service-management-l1-1-0.dll", "api-ms-win-service-management-l2-1-0.dll", "api-ms-win-service-winsvc-l1-1-0.dll", "apphelp.dll", "appidapi.dll", "appmgmts.dll", "appwiz.cpl", "atl.dll", "authz.dll", "avicap32.dll", "avifil32.dll", "avrt.dll", "batmeter.dll", "bcrypt.dll", "browcli.dll", "bthprops.cpl", "cabinet.dll", "certcli.dll", "certenroll.dll", "cfgmgr32.dll", "clbcatq.dll", "clb.dll", "clfsw32.dll", "clusapi.dll", "cmpbk32.dll", "cmutil.dll", "colorui.dll", "comctl32.dll", "comdlg32.dll", "comsvcs.dll", "connect.dll", "credui.dll", "crypt32.dll", "cryptbase.dll", "cryptdll.dll", "cryptsp.dll", "cryptui.dll", "cryptxml.dll", "d2d1.dll", "d3d10_1core.dll", "d3d10_1.dll", "d3d10core.dll", "d3d10.dll", "d3d11.dll", "d3d8thk.dll", "d3d9.dll", "davhlpr.dll", "dbghelp.dll", "dciman32.dll", "ddraw.dll", "devobj.dll", "devrtl.dll", "dfscli.dll", "dhcpcsvc6.dll", "dhcpcsvc.dll", "dinput.dll", "dmdskmgr.dll", "dmutil.dll", "dnsapi.dll", "dot3api.dll", "dplayx.dll", "dpnet.dll", "dpx.dll", "drvstore.dll", "dsauth.dll", "dsound.dll", "dsrole.dll", "dssec.dll", "dsuiext.dll", "dui70.dll", "duser.dll", "dwmapi.dll", "dwrite.dll", "dxgidebug.dll", "dxgi.dll", "dxtrans.dll", "dxva2.dll", "eappcfg.dll", "eappprxy.dll", "efsadu.dll", "efsutil.dll", "esent.dll", "evr.dll", "explorerframe.dll", "faultrep.dll", "firewallapi.dll", "fltlib.dll", "framedynos.dll", "fxsapi.dll", "gdi32.dll", "getuname.dll", "glu32.dll", "gpapi.dll", "gpedit.dll", "hhsetup.dll", "hid.dll", "httpapi.dll", "iashlpr.dll", "iasrad.dll", "iassvcs.dll", "icmp.dll", "ieakeng.dll", "ieframe.dll", "iertutil.dll", "ifsutil.dll", "imagehlp.dll", "imm32.dll", "inetcomm.dll", "input.dll", "iprtprio.dll", "iscsidsc.dll", "iscsied.dll", "iscsium.dll", "kernel32.dll", "kernelbase.dll", "ksuser.dll", "ktmw32.dll", "l2gpstore.dll", "linkinfo.dll", "loadperf.dll", "logoncli.dll", "lpk.dll", "lz32.dll", "magnification.dll", "mapi32.dll", "mcewmdrmndbootstrap.dll", "mfc110d.dll", "mfc110ud.dll", "mfcsubs.dll", "mf.dll", "mfplat.dll", "mlang.dll", "mmcbase.dll", "mmdevapi.dll", "mprapi.dll", "mpr.dll", "msacm32.dll", "msasn1.dll", "mscms.dll", "mscoree.dll", "msctf.dll", "msctfmonitor.dll", "msdmo.dll", "msdrm.dll", "msdtcprx.dll", "msi.dll", "msimg32.dll", "msjet40.dll", "msjint40.dll", "msjter40.dll", "msls31.dll", "msoert2.dll", "msports.dll", "msshooks.dll", "mssrch.dll", "msswch.dll", "mstscax.dll", "msutb.dll", "msv1_0.dll", "msvcirt.dll", "msvcp110d.dll", "msvcp110.dll", "msvcp60.dll", "msvcr100.dll", "msvcr110_clr0400.dll", "msvcr110d.dll", "msvcr110.dll", "msvcrt40.dll", "msvcrt.dll", "msvfw32.dll", "mswsock.dll", "mswstr10.dll", "mtxclu.dll", "nci.dll", "ncrypt.dll", "ndfapi.dll", "netapi32.dll", "netdiagfx.dll", "netjoin.dll", "netplwiz.dll", "netshell.dll", "netsh.exe", "netutils.dll", "newdev.dll", "nlaapi.dll", "nsi.dll", "ntdll.dll", "ntdsapi.dll", "ntoskrnl.exe", "ntshrui.dll", "odbc32.dll", "odbcjt32.dll", "ole32.dll", "oleacc.dll", "oleaut32.dll", "onex.dll", "onexui.dll", "opcservices.dll", "opengl32.dll", "osuninst.dll", "p2pcollab.dll", "p2p.dll", "pcwum.dll", "pdh.dll", "pdhui.dll", "pla.dll", "playsndsrv.dll", "polstore.dll", "powrprof.dll", "prntvpt.dll", "profapi.dll", "propsys.dll", "psapi.dll", "puiapi.dll", "quartz.dll", "rasapi32.dll", "rasdlg.dll", "rasman.dll", "rdpcore.dll", "reagent.dll", "regapi.dll", "resutils.dll", "riched20.dll", "rpcdiag.dll", "rpcrt4.dll", "rstrtmgr.dll", "rtm.dll", "rtutils.dll", "samcli.dll", "samlib.dll", "scansetting.dll", "scecli.dll", "schedcli.dll", "secur32.dll", "sensapi.dll", "setupapi.dll", "sfc.dll", "sfc_os.dll", "shdocvw.dll", "shell32.dll", "shlwapi.dll", "shunimpl.dll", "slc.dll", "slwga.dll", "snmpapi.dll", "sppc.dll", "sppcext.dll", "spp.dll", "sqmapi.dll", "srvcli.dll", "ssdpapi.dll", "sspicli.dll", "sti.dll", "sxshared.dll", "synceng.dll", "sysdm.cpl", "syssetup.dll", "tapi32.dll", "tdh.dll", "tquery.dll", "traffic.dll", "ufat.dll", "ulib.dll", "uniplat.dll", "untfs.dll", "urlmon.dll", "user32.dll", "userenv.dll", "usp10.dll", "utildll.dll", "uxlib.dll", "uxtheme.dll", "vaultcli.dll", "vdmdbg.dll", "version.dll", "virtdisk.dll", "vssapi.dll", "vsstrace.dll", "wabsyncprovider.dll", "wbemcomn.dll", "wdi.dll", "wdscore.dll", "webio.dll", "webservices.dll", "wecapi.dll", "wer.dll", "wevtapi.dll", "winbio.dll", "winbrand.dll", "windowscodecs.dll", "winhttp.dll", "wininet.dll", "winipsec.dll", "winmm.dll", "winnsi.dll", "winscard.dll", "winspool.drv", "winsta.dll", "winsync.dll", "winsyncmetastore.dll", "winsyncproviders.dll", "wintrust.dll", "wkscli.dll", "wlanapi.dll", "wlanhlp.dll", "wlansec.dll", "wlanui.dll", "wlanutil.dll", "wldap32.dll", "wmdrmsdk.dll", "wmi.dll", "wmsgapi.dll", "wow32.dll", "ws2_32.dll", "ws2help.dll", "wscapi.dll", "wscui.cpl", "wsdapi.dll", "wsmsvc.dll", "wsnmp32.dll", "wsock32.dll", "wtsapi32.dll", "wwapi.dll", "xmllite.dll", "xpsgdiconverter.dll", "xpsservices.dll", "xpssvcs.dll"]
libs = {}

def init_libs(addr):
	inst = getInstructionAt(addr)
	# TODO: use pcode and reaching definition
	while not inst.toString().startswith('XOR EAX,0x'):
		inst = inst.getNext()
	xor_value = inst.getScalar(1).getValue()

	for dll_name in dll_names:
		accu = 0
		for c in dll_name:
			tmp = ord(c)
			if 0x40 < ord(c) and ord(c) < 0x5b:
				tmp = tmp + 0x20
			accu = (tmp + accu * 0x1003f)%2**32;
		hash = accu ^ xor_value
		libs.update({hash:dll_name})
	

def get_lib(hash):
	dll_name = libs.get(hash)
	if dll_name is None:
		print "ERROR: Could not find dll name for hash " + str(hash)
		return "Unknown"
	return dll_name

init_libs(currentAddress)

enum = EnumDataType('emotet_lib_hash',4)
for lib in libs:
	enum.add(libs[lib], lib)
dtm = currentProgram.getDataTypeManager()
dtm.addDataType(enum,None)

refs = getReferencesTo(currentAddress)

for r in refs:
	callee = r.getFromAddress()
	inst = inst_ = getInstructionAt(callee)
	i = 0
	# TODO: use pcode and reaching definition
	while not inst.toString().startswith('MOV ECX,0x'):
		inst = getInstructionBefore(inst)
		i += 1
		if i > 10:
			break
	if inst.toString().startswith('MOV ECX,0x'):
		try:
			dll_name = get_lib(inst.getScalar(1).getValue())
		except Exception as e:
			print(str(callee) + " FAIL 1")
		else:
			inst_.setComment(CodeUnit.EOL_COMMENT,dll_name)
			createBookmark(callee, "emotet lib", dll_name)
			print str(callee)+" "+str(dll_name)
	else:
		print(str(callee) + " FAIL 2")


