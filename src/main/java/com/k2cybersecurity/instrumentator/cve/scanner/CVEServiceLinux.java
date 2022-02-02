package com.k2cybersecurity.instrumentator.cve.scanner;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.os.OSVariables;
import com.k2cybersecurity.instrumentator.os.OsVariablesInstance;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.NameFileFilter;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.CVEPackageInfo;
import com.k2cybersecurity.intcodeagent.models.javaagent.CVEScanner;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class CVEServiceLinux extends CVEScan {

    private static final String ERROR_LOG = "Error : ";

    private static final String CANNOT_CREATE_DIRECTORY = "Cannot create directory : ";

    private static final String ERROR_PROCESS_TERMINATED = "Error Process terminated: {}";

    private static final String ERROR = "Error: {}";

    private static final String K2_VULNERABILITY_SCANNER_RESPONSE_ERROR = "K2 Vulnerability scanner response error : %s";

    private static final String K2_VULNERABILITY_SCANNER_RESPONSE = "K2 Vulnerability scanner response : %s";

    private static final String LOCALCVESERVICE_PATH = "localcveservice";

    public static final String KILL_PROCESS_TREE_COMMAND = "kill -9 -%s";
    public static final String KILLING_PROCESS_TREE_ROOTED_AT_S = "Killing process tree rooted at : %s";
    public static final String SETSID = "setsid";
    public static final String CORRUPTED_CVE_SERVICE_BUNDLE_DELETED = "Corrupted CVE service bundle deleted.";

    public static final String LINUX_SHELL = "sh";
    public static final String PATH_TO_DEPENDENCY_CHECK = "/K2/dependency-check.sh";
    public static final String STARTUP_SH_PATH = "K2/startup.sh";

    private String nodeId;

    private String kind;

    private String id;

    private boolean isEnvScan;

    private CVEPackageInfo packageInfo;

    private Process liveProcess;

    private OSVariables osVariables = OsVariablesInstance.getInstance().getOsVariables();

    public CVEServiceLinux(String nodeId, String kind, String id, CVEPackageInfo packageInfo, boolean isEnvScan) {
        this.nodeId = nodeId;
        this.kind = kind;
        this.id = id;
        this.packageInfo = packageInfo;
        this.isEnvScan = isEnvScan;
    }

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    @Override
    public void run() {
        boolean runStatus = false;
        try {
            String packageParentDir = osVariables.getTmpDirectory();
            logger.log(LogLevel.DEBUG, String.format(ICVEConstants.PACKAGE_INFO_LOGGER, packageInfo.toString(), CVEScannerPool.getInstance().getPackageInfo()), CVEServiceLinux.class.getName());
            if (CVEScannerPool.getInstance().getPackageInfo() == null || !CVEScannerPool.getInstance().getPackageInfo().getCvePackage().exists() || !StringUtils.equals(packageInfo.getLatestServiceVersion(), CVEScannerPool.getInstance().getPackageInfo().getLatestServiceVersion())) {
                Collection<File> cvePackages = FileUtils.listFiles(new File(osVariables.getTmpDirectory()), new NameFileFilter(ICVEConstants.LOCALCVESERVICE), null);
                logger.log(LogLevel.DEBUG, ICVEConstants.FILES_TO_DELETE + cvePackages, CVEServiceLinux.class.getName());
                cvePackages.forEach(FileUtils::deleteQuietly);
                CVEComponentsService.downloadCVEPackage(packageInfo);
            }
            if (CVEScannerPool.getInstance().getPackageInfo() == null || !CVEScannerPool.getInstance().getPackageInfo().getCvePackage().exists()) {
                return;
            }
            logger.log(LogLevel.DEBUG, ICVEConstants.CVE_PACKAGE_DOWNLOADED, CVEServiceLinux.class.getName());
            //Create untar Directory
            File packageExtractedDirectory = new File(packageParentDir, LOCALCVESERVICE_PATH);
            FileUtils.deleteQuietly(packageExtractedDirectory);
            if (!packageExtractedDirectory.exists()) {
                try {
                    packageExtractedDirectory.mkdirs();
                } catch (Throwable e) {
                    logger.log(LogLevel.ERROR, CANNOT_CREATE_DIRECTORY + packageExtractedDirectory, e,
                            CVEServiceLinux.class.getName());
                    return;
                }
            }

            AgentUtils.extractCVETar(CVEScannerPool.getInstance().getPackageInfo().getCvePackage(), packageExtractedDirectory);
            FileUtils.deleteQuietly(CVEScannerPool.getInstance().getPackageInfo().getCvePackage());
            CVEComponentsService.setAllLinuxPermissions(packageExtractedDirectory.getAbsolutePath());
            logger.log(LogLevel.DEBUG, ICVEConstants.CVE_PACKAGE_EXTRACTION_COMPLETED, CVEServiceLinux.class.getName());
            StringBuilder dcCommand = new StringBuilder(LINUX_SHELL);
            dcCommand.append(StringUtils.SPACE);
            dcCommand.append(packageExtractedDirectory.getAbsolutePath());
            dcCommand.append(PATH_TO_DEPENDENCY_CHECK);

            String startupScriptPath = new File(packageExtractedDirectory.getAbsolutePath(), STARTUP_SH_PATH).getAbsolutePath();

            List<CVEScanner> scanDirs;
            if (isEnvScan) {
                scanDirs = CVEComponentsService.getLibScanDirs();
            } else {
                scanDirs = CVEComponentsService.getAppScanDirs();
            }
            for (CVEScanner scanner : scanDirs) {
                File inputYaml = CVEComponentsService.createServiceYml(dcCommand.toString(), nodeId, scanner.getAppName(),
                        scanner.getAppSha256(), scanner.getDir(),
                        K2Instrumentator.APPLICATION_INFO_BEAN.getApplicationUUID(), scanner.getEnv(), kind, id, packageExtractedDirectory.getAbsolutePath());
                List<String> paramList = Arrays.asList(SETSID, LINUX_SHELL, startupScriptPath,
                        inputYaml.getAbsolutePath());
                ProcessBuilder processBuilder = new ProcessBuilder(paramList);
                File dcout = Paths.get(packageExtractedDirectory.getAbsolutePath(), ICVEConstants.DC_TRIGGER_LOG).toFile();
                processBuilder.redirectErrorStream(true);
                processBuilder.redirectOutput(dcout);
                liveProcess = processBuilder.start();
                if (!liveProcess.waitFor(10, TimeUnit.MINUTES)) {
                    long pid = AgentUtils.getInstance().getProcessID(liveProcess);
                    if (pid > 1) {
                        logger.log(LogLevel.WARN, String.format(KILLING_PROCESS_TREE_ROOTED_AT_S, pid), CVEServiceLinux.class.getName());
                        AgentUtils.getInstance().incrementCVEServiceFailCount();
                        Runtime.getRuntime().exec(String.format(KILL_PROCESS_TREE_COMMAND, pid));
                    }
                } else if (liveProcess.exitValue() != 0) {
                    AgentUtils.getInstance().incrementCVEServiceFailCount();
                }
//                List<String> response = IOUtils.readLines(process.getInputStream(), StandardCharsets.UTF_8);
//                logger.log(LogLevel.INFO,
//                        String.format(K2_VULNERABILITY_SCANNER_RESPONSE, StringUtils.join(response, StringUtils.LF)),
//                        CVEServiceLinux.class.getName());
//                List<String> errResponse = IOUtils.readLines(process.getErrorStream(), StandardCharsets.UTF_8);
//                logger.log(LogLevel.ERROR, String.format(K2_VULNERABILITY_SCANNER_RESPONSE_ERROR,
//                        StringUtils.join(errResponse, StringUtils.LF)), CVEServiceLinux.class.getName());

                logger.log(LogLevel.INFO,
                        String.format(K2_VULNERABILITY_SCANNER_RESPONSE, FileUtils.readFileToString(Paths.get(packageExtractedDirectory.getAbsolutePath(), ICVEConstants.DC_TRIGGER_LOG).toFile(), Charset.defaultCharset())),
                        CVEServiceLinux.class.getName());
                try {
                    FileUtils.forceDelete(inputYaml);
                } catch (Throwable e) {
                }
            }
            CVEComponentsService.deleteAllComponents(osVariables.getTmpDirectory());
            logger.log(LogLevel.DEBUG, ICVEConstants.CVE_PACKAGE_DELETED, CVEServiceLinux.class.getName());
            runStatus = true;
            return;
        } catch (InterruptedException e) {
            logger.log(LogLevel.ERROR, ERROR_PROCESS_TERMINATED, e, CVEServiceLinux.class.getName());
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, ERROR, e, CVEServiceLinux.class.getName());
        } finally {
            if (!runStatus && this.isEnvScan) {
                AgentUtils.getInstance().setCveEnvScanCompleted(false);
            }
        }

    }

    @Override
    public void destroyForcibly() {
        if (liveProcess != null) {
            long pid = AgentUtils.getInstance().getProcessID(liveProcess);
            if (pid > 1) {
                logger.log(LogLevel.WARN, String.format(KILLING_PROCESS_TREE_ROOTED_AT_S, pid), CVEServiceLinux.class.getName());
                AgentUtils.getInstance().incrementCVEServiceFailCount();
                try {
                    Runtime.getRuntime().exec(String.format(KILL_PROCESS_TREE_COMMAND, pid));
                } catch (IOException e) {
                    liveProcess.destroyForcibly();
                }
            }
        }
    }
}
