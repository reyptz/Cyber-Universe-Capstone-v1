import { useQuery } from '@tanstack/react-query';
import { 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  TrendingUp,
  Target,
  Database,
  Shield,
  Clock
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { api } from '../lib/api';

interface Metrics {
  missions: {
    total: number;
    active: number;
    completed: number;
  };
  results: {
    total: number;
    to_validate: number;
  };
  workflow: {
    total_items: number;
    in_progress: number;
  };
  detection: {
    rules_count: number;
    enabled_rules: number;
  };
}

export function Dashboard() {
  const { data: metrics, isLoading } = useQuery<Metrics>({
    queryKey: ['metrics'],
    queryFn: api.getMetrics,
    refetchInterval: 5000, // Refresh every 5s
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  const stats = [
    {
      title: 'Active Missions',
      value: metrics?.missions.active || 0,
      total: metrics?.missions.total || 0,
      icon: Target,
      color: 'text-blue-600',
      bgColor: 'bg-blue-100',
    },
    {
      title: 'Data Collected',
      value: metrics?.results.total || 0,
      subtitle: `${metrics?.results.to_validate || 0} to validate`,
      icon: Database,
      color: 'text-green-600',
      bgColor: 'bg-green-100',
    },
    {
      title: 'Workflow Items',
      value: metrics?.workflow.in_progress || 0,
      total: metrics?.workflow.total_items || 0,
      icon: Activity,
      color: 'text-orange-600',
      bgColor: 'bg-orange-100',
    },
    {
      title: 'Detection Rules',
      value: metrics?.detection.enabled_rules || 0,
      total: metrics?.detection.rules_count || 0,
      icon: Shield,
      color: 'text-purple-600',
      bgColor: 'bg-purple-100',
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
        <div className="flex items-center space-x-2 text-sm text-gray-500">
          <Clock className="h-4 w-4" />
          <span>Last updated: {new Date().toLocaleTimeString()}</span>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat) => {
          const Icon = stat.icon;
          return (
            <Card key={stat.title}>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">
                      {stat.title}
                    </p>
                    <div className="flex items-baseline space-x-2 mt-2">
                      <p className="text-3xl font-bold text-gray-900">
                        {stat.value}
                      </p>
                      {stat.total !== undefined && (
                        <p className="text-sm text-gray-500">/ {stat.total}</p>
                      )}
                    </div>
                    {stat.subtitle && (
                      <p className="text-sm text-gray-500 mt-1">{stat.subtitle}</p>
                    )}
                  </div>
                  <div className={`p-3 rounded-lg ${stat.bgColor}`}>
                    <Icon className={`h-6 w-6 ${stat.color}`} />
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Activity className="h-5 w-5" />
              <span>Recent Activity</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[
                {
                  action: 'Mission Created',
                  target: 'Target Analysis #42',
                  time: '2 minutes ago',
                  status: 'success',
                },
                {
                  action: 'Detection Alert',
                  target: 'Suspicious Network Activity',
                  time: '15 minutes ago',
                  status: 'warning',
                },
                {
                  action: 'Workflow Validated',
                  target: 'OSINT Report #128',
                  time: '1 hour ago',
                  status: 'success',
                },
              ].map((activity, idx) => (
                <div key={idx} className="flex items-center justify-between py-2 border-b last:border-0">
                  <div className="flex items-center space-x-3">
                    {activity.status === 'success' ? (
                      <CheckCircle className="h-5 w-5 text-green-600" />
                    ) : (
                      <AlertTriangle className="h-5 w-5 text-orange-600" />
                    )}
                    <div>
                      <p className="text-sm font-medium text-gray-900">
                        {activity.action}
                      </p>
                      <p className="text-sm text-gray-500">{activity.target}</p>
                    </div>
                  </div>
                  <span className="text-xs text-gray-400">{activity.time}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <TrendingUp className="h-5 w-5" />
              <span>Performance Metrics</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-700">
                    Collection Rate
                  </span>
                  <span className="text-sm font-bold text-green-600">
                    850 pages/min
                  </span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-green-600 h-2 rounded-full"
                    style={{ width: '85%' }}
                  ></div>
                </div>
                <p className="text-xs text-gray-500 mt-1">
                  Target: 1000 pages/min
                </p>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-700">
                    Detection Latency
                  </span>
                  <span className="text-sm font-bold text-green-600">
                    145 ms
                  </span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-green-600 h-2 rounded-full"
                    style={{ width: '72%' }}
                  ></div>
                </div>
                <p className="text-xs text-gray-500 mt-1">Target: &lt; 200 ms</p>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-700">
                    System Uptime
                  </span>
                  <span className="text-sm font-bold text-green-600">
                    99.7%
                  </span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-green-600 h-2 rounded-full"
                    style={{ width: '99.7%' }}
                  ></div>
                </div>
                <p className="text-xs text-gray-500 mt-1">Target: 99.5% SLA</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
