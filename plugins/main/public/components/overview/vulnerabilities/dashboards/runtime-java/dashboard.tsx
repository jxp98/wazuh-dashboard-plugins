import React from 'react';
import { IntlProvider } from 'react-intl';
import { EuiPageTemplate } from '@elastic/eui';
import { compose } from 'redux';
import { IndexPattern } from '../../../../../../../../src/plugins/data/public';
import {
  HideOnErrorInitializatingDataSource,
  PromptErrorInitializatingDataSource,
  withErrorBoundary,
} from '../../../../common/hocs';
import { WzSearchBar } from '../../../../common/search-bar';
import useSearchBar from '../../../../common/search-bar/use-search-bar';
import { LoadingSearchbarProgress } from '../../../../../../public/components/common/loading-searchbar-progress/loading-searchbar-progress';
import { ModuleEnabledCheck } from '../../common/components/check-module-enabled';
import { withRuntimeJavaVulnerabilitiesStateDataSource } from '../../common/hocs/validate-vulnerabilities-states-index-pattern';
import {
  PatternDataSource,
  RuntimeJavaVulnerabilitiesDataSourceRepository,
  tParsedIndexPattern,
  VulnerabilitiesDataSource,
} from '../../../../common/data-source';
import { useDataSource } from '../../../../common/data-source/hooks';
import { RuntimeJavaVulnerabilitiesSummary } from './summary';

const RuntimeJavaVulnerabilitiesDashboardComponent = () => {
  const {
    dataSource,
    filters,
    fetchFilters,
    fixedFilters,
    isLoading: isDataSourceLoading,
    fetchData,
    setFilters,
    error,
  } = useDataSource<tParsedIndexPattern, PatternDataSource>({
    DataSource: VulnerabilitiesDataSource,
    repository: new RuntimeJavaVulnerabilitiesDataSourceRepository(),
  });
  const { searchBarProps, fingerprint } = useSearchBar({
    indexPattern: dataSource?.indexPattern as IndexPattern,
    filters,
    setFilters,
  });
  const { query } = searchBarProps;

  return (
    <IntlProvider locale='en'>
      <>
        <ModuleEnabledCheck />
        <EuiPageTemplate
          className='vulsInventoryContainer'
          restrictWidth='100%'
          fullHeight={true}
          grow
          paddingSize='none'
          pageContentProps={{ color: 'transparent' }}
        >
          <>
            {isDataSourceLoading ? (
              <LoadingSearchbarProgress />
            ) : (
              <HideOnErrorInitializatingDataSource error={error}>
                <WzSearchBar
                  appName='runtime-java-vulnerabilities'
                  {...searchBarProps}
                  fixedFilters={fixedFilters}
                  showDatePicker={false}
                  showQueryInput={true}
                  showQueryBar={true}
                  showSaveQuery={true}
                />
              </HideOnErrorInitializatingDataSource>
            )}

            {!isDataSourceLoading && !error ? (
              <RuntimeJavaVulnerabilitiesSummary
                fetchData={fetchData}
                query={query}
                isLoading={isDataSourceLoading}
                fingerprint={fingerprint}
                filtersFingerprint={JSON.stringify(fetchFilters)}
              />
            ) : null}
          </>
          {error && <PromptErrorInitializatingDataSource error={error} />}
        </EuiPageTemplate>
      </>
    </IntlProvider>
  );
};

export const RuntimeJavaVulnerabilitiesDashboard = compose(
  withErrorBoundary,
  withRuntimeJavaVulnerabilitiesStateDataSource,
)(RuntimeJavaVulnerabilitiesDashboardComponent);
