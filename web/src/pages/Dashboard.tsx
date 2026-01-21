import { useEffect, useState } from 'react'
import { Row, Col, Card, Statistic, Spin } from 'antd'
import {
  UserOutlined,
  TeamOutlined,
  AppstoreOutlined,
  SafetyOutlined,
  KeyOutlined,
} from '@ant-design/icons'
import { usersApi, organizationsApi, applicationsApi, rolesApi, permissionsApi } from '../api/client'

export default function Dashboard() {
  const [loading, setLoading] = useState(true)
  const [stats, setStats] = useState({
    users: 0,
    organizations: 0,
    applications: 0,
    roles: 0,
    permissions: 0,
  })

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const [users, orgs, apps, roles, perms] = await Promise.all([
          usersApi.list({ page_size: 1 }),
          organizationsApi.list({ page_size: 1 }),
          applicationsApi.list({ page_size: 1 }),
          rolesApi.list({ page_size: 1 }),
          permissionsApi.list({ page_size: 1 }),
        ])
        setStats({
          users: users.data.total,
          organizations: orgs.data.total,
          applications: apps.data.total,
          roles: roles.data.total,
          permissions: perms.data.total,
        })
      } catch (error) {
        console.error('Failed to fetch stats:', error)
      } finally {
        setLoading(false)
      }
    }
    fetchStats()
  }, [])

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: 50 }}>
        <Spin size="large" />
      </div>
    )
  }

  return (
    <div>
      <h2 style={{ marginBottom: 24 }}>Dashboard</h2>
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={8}>
          <Card>
            <Statistic
              title="Total Users"
              value={stats.users}
              prefix={<UserOutlined />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={8}>
          <Card>
            <Statistic
              title="Organizations"
              value={stats.organizations}
              prefix={<TeamOutlined />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={8}>
          <Card>
            <Statistic
              title="Applications"
              value={stats.applications}
              prefix={<AppstoreOutlined />}
              valueStyle={{ color: '#722ed1' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={8}>
          <Card>
            <Statistic
              title="Roles"
              value={stats.roles}
              prefix={<SafetyOutlined />}
              valueStyle={{ color: '#fa8c16' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={8}>
          <Card>
            <Statistic
              title="Permissions"
              value={stats.permissions}
              prefix={<KeyOutlined />}
              valueStyle={{ color: '#eb2f96' }}
            />
          </Card>
        </Col>
      </Row>
    </div>
  )
}
