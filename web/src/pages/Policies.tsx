import { useEffect, useState } from 'react'
import {
  Table,
  Button,
  Space,
  Modal,
  Form,
  Input,
  Select,
  message,
  Popconfirm,
  Tag,
  Card,
  Row,
  Col,
} from 'antd'
import { PlusOutlined, DeleteOutlined, CheckCircleOutlined, CloseCircleOutlined } from '@ant-design/icons'
import { policiesApi, Policy } from '../api/client'

export default function Policies() {
  const [loading, setLoading] = useState(false)
  const [policies, setPolicies] = useState<Policy[]>([])
  const [modalOpen, setModalOpen] = useState(false)
  const [enforceModalOpen, setEnforceModalOpen] = useState(false)
  const [enforceResult, setEnforceResult] = useState<boolean | null>(null)
  const [form] = Form.useForm()
  const [enforceForm] = Form.useForm()

  const fetchPolicies = async () => {
    setLoading(true)
    try {
      const res = await policiesApi.list()
      setPolicies(res.data.data)
    } catch (error) {
      message.error('Failed to fetch policies')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchPolicies()
  }, [])

  const handleCreate = () => {
    form.resetFields()
    form.setFieldsValue({ ptype: 'p' })
    setModalOpen(true)
  }

  const handleDelete = async (policy: Policy) => {
    try {
      await policiesApi.remove({
        ptype: policy.ptype,
        v0: policy.v0,
        v1: policy.v1,
        v2: policy.v2,
      })
      message.success('Policy deleted')
      fetchPolicies()
    } catch (error) {
      message.error('Failed to delete policy')
    }
  }

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields()
      await policiesApi.add(values)
      message.success('Policy added')
      setModalOpen(false)
      fetchPolicies()
    } catch (error: any) {
      if (error.errorFields) return
      message.error(error.response?.data?.details || 'Operation failed')
    }
  }

  const handleEnforce = async () => {
    try {
      const values = await enforceForm.validateFields()
      const res = await policiesApi.enforce(values.sub, values.obj, values.act)
      setEnforceResult(res.data.allowed)
    } catch (error: any) {
      if (error.errorFields) return
      message.error(error.response?.data?.details || 'Enforce failed')
    }
  }

  const columns = [
    {
      title: 'Type',
      dataIndex: 'ptype',
      key: 'ptype',
      render: (ptype: string) =>
        ptype === 'p' ? <Tag color="blue">Policy</Tag> : <Tag color="green">Grouping</Tag>,
    },
    {
      title: 'Subject (v0)',
      dataIndex: 'v0',
      key: 'v0',
    },
    {
      title: 'Object (v1)',
      dataIndex: 'v1',
      key: 'v1',
    },
    {
      title: 'Action (v2)',
      dataIndex: 'v2',
      key: 'v2',
      render: (v2: string) => v2 || '-',
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_: any, record: Policy) => (
        <Space>
          <Popconfirm
            title="Delete this policy?"
            onConfirm={() => handleDelete(record)}
          >
            <Button icon={<DeleteOutlined />} danger />
          </Popconfirm>
        </Space>
      ),
    },
  ]

  return (
    <div>
      <div className="page-header">
        <h2 className="page-title">Casbin Policies</h2>
        <Space>
          <Button onClick={() => setEnforceModalOpen(true)}>
            Test Permission
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
            Add Policy
          </Button>
        </Space>
      </div>

      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card title="Policy Rules" size="small">
            <Table
              columns={columns}
              dataSource={policies}
              rowKey={(record) => `${record.ptype}-${record.v0}-${record.v1}-${record.v2}`}
              loading={loading}
              pagination={false}
            />
          </Card>
        </Col>
      </Row>

      <Modal
        title="Add Policy"
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => setModalOpen(false)}
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="ptype"
            label="Policy Type"
            rules={[{ required: true }]}
          >
            <Select>
              <Select.Option value="p">Policy (p)</Select.Option>
              <Select.Option value="g">Grouping (g)</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item
            name="v0"
            label="Subject (v0)"
            rules={[{ required: true }]}
            tooltip="User or role name"
          >
            <Input placeholder="e.g., admin, user123" />
          </Form.Item>
          <Form.Item
            name="v1"
            label="Object (v1)"
            rules={[{ required: true }]}
            tooltip="For policy: resource path. For grouping: role name"
          >
            <Input placeholder="e.g., /api/users, admin_role" />
          </Form.Item>
          <Form.Item
            noStyle
            shouldUpdate={(prev, cur) => prev.ptype !== cur.ptype}
          >
            {({ getFieldValue }) =>
              getFieldValue('ptype') === 'p' ? (
                <Form.Item
                  name="v2"
                  label="Action (v2)"
                  rules={[{ required: true }]}
                  tooltip="Action type"
                >
                  <Input placeholder="e.g., read, write, delete, *" />
                </Form.Item>
              ) : null
            }
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="Test Permission"
        open={enforceModalOpen}
        onOk={handleEnforce}
        onCancel={() => {
          setEnforceModalOpen(false)
          setEnforceResult(null)
        }}
        okText="Test"
      >
        <Form form={enforceForm} layout="vertical">
          <Form.Item
            name="sub"
            label="Subject"
            rules={[{ required: true }]}
          >
            <Input placeholder="e.g., admin" />
          </Form.Item>
          <Form.Item
            name="obj"
            label="Object"
            rules={[{ required: true }]}
          >
            <Input placeholder="e.g., /api/users" />
          </Form.Item>
          <Form.Item
            name="act"
            label="Action"
            rules={[{ required: true }]}
          >
            <Input placeholder="e.g., read" />
          </Form.Item>
        </Form>
        {enforceResult !== null && (
          <div style={{ textAlign: 'center', marginTop: 16 }}>
            {enforceResult ? (
              <Tag icon={<CheckCircleOutlined />} color="success" style={{ fontSize: 16, padding: '8px 16px' }}>
                ALLOWED
              </Tag>
            ) : (
              <Tag icon={<CloseCircleOutlined />} color="error" style={{ fontSize: 16, padding: '8px 16px' }}>
                DENIED
              </Tag>
            )}
          </div>
        )}
      </Modal>
    </div>
  )
}
