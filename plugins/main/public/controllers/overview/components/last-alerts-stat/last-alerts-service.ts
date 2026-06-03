import { AppState } from '../../../../react-services/app-state';
import { search } from '../../../../components/common/search-bar';
import { getDataPlugin } from '../../../../kibana-services';
import { getLastAlertsQuery } from './last-alerts-query';
import { PatternDataSourceFilterManager } from '../../../../components/common/data-source/pattern/pattern-data-source-filter-manager';
import { ErrorDataSourceServerAPIContextFilter } from '../../../../utils/errors';

interface Last24HoursAlerts {
  count: number;
  cluster?: {
    field: string;
    name: string;
  };
  indexPatternId: string;
}

/**
 * This fetch the last 24 hours alerts from the selected cluster
 * TODO: The search function should be moved to a common place
 */
export const getLast24HoursAlerts = async (
  ruleLevel: string,
): Promise<Last24HoursAlerts> => {
  try {
    const patternId = AppState.getCurrentPattern();
    const currentIndexPattern = await getDataPlugin().indexPatterns.get(
      patternId,
    );
    const clusterInfo = AppState.getClusterInfo();
    const clusterValue =
      PatternDataSourceFilterManager.getClusterFilterValue(clusterInfo);

    if (
      clusterValue === undefined &&
      !PatternDataSourceFilterManager.isClusterModeDisabled(clusterInfo)
    ) {
      throw new ErrorDataSourceServerAPIContextFilter(
        'Filter could not be created because no server API is selected. Make sure a server API is available and choose one in the selector.',
      );
    }

    const lastAlertsQuery = getLastAlertsQuery(
      currentIndexPattern,
      ruleLevel,
      clusterValue,
    );

    const result = await search(lastAlertsQuery);
    const count = result?.hits?.total;
    return {
      count,
      ...(clusterValue
        ? {
            cluster: {
              field: 'cluster.name',
              name: clusterValue,
            },
          }
        : {}),
      indexPatternId: currentIndexPattern.id,
    };
  } catch (error) {
    return Promise.reject(error);
  }
};
