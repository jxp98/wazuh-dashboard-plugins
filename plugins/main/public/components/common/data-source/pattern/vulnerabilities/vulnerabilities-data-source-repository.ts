import {
  WAZUH_RUNTIME_JAVA_VULNERABILITIES_HISTORY_PATTERN,
  WAZUH_RUNTIME_JAVA_VULNERABILITIES_PATTERN,
  WAZUH_VULNERABILITIES_PATTERN,
} from '../../../../../../common/constants';
import { createPatternDataSourceRepositoryUseValue } from '../pattern-data-source-repository-use-setting-value';

export const VulnerabilitiesDataSourceRepository =
  createPatternDataSourceRepositoryUseValue(WAZUH_VULNERABILITIES_PATTERN);

export const RuntimeJavaVulnerabilitiesDataSourceRepository =
  createPatternDataSourceRepositoryUseValue(
    WAZUH_RUNTIME_JAVA_VULNERABILITIES_PATTERN,
  );

export const RuntimeJavaVulnerabilitiesHistoryDataSourceRepository =
  createPatternDataSourceRepositoryUseValue(
    WAZUH_RUNTIME_JAVA_VULNERABILITIES_HISTORY_PATTERN,
  );
