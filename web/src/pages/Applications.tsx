import { useEffect, useState } from 'react'
import {
  Table,
  Button,
  Space,
  Modal,
  Form,
  Input,
  InputNumber,
  message,
  Popconfirm,
  Typography,
  Tooltip,
} from 'antd'
import { PlusOutlined, EditOutlined, DeleteOutlined, CopyOutlined } from '@ant-design/icons'
import { applicationsApi, Application } from '../api/client'

const { Paragraph } = Typography

export default function Applications() {
  const [loading, setLoading] = useState(false)
  const [applications, setApplications] = useState<Application[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [modalOpen, setModalOpen] = useState(false)
  const [editingApp, setEditingApp] = useState<Application | null>(null)
  const [form] = Form.useForm()

  const fetchApplications = async () => {
    setLoading(true)
    try {
      const res = await applicationsApi.list({ page, page_size: pageSize })
      setApplications(res.data.data)
      setTotal(res.data.total)
    } catch (error) {
      message.error('Failed to fetch applications')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchApplications()
  }, [page, pageSize])

  const handleCreate = () => {
    setEditingApp(null)
    form.resetFields()
    form.setFieldsValue({
      owner: 'admin',
      organization: 'built-in',
      token_format: 'JWT',
      expire_in_hours: 24,
    })
    setModalOpen(true)
  }

  const handleEdit = (app: Application) => {
    setEditingApp(app)
    form.setFieldsValue(app)
    setModalOpen(true)
  }

  const handleDelete = async (id: string) => {
    try {
      await applicationsApi.delete(id)
      message.success('Application deleted')
      fetchApplications()
    } catch (error) {
      message.error('Failed to delete application')
    }
  }

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields()
      if (editingApp) {
        await applicationsApi.update(editingApp.id, values)
        message.success('Application updated')
      } else {
        await applicationsApi.create(values)
        message.success('Application created')
      }
      setModalOpen(false)
      fetchApplications()
    } catch (error: any) {
      if (error.errorFields) return
      message.error(error.response?.data?.details || 'Operation failed')
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    message.success('Copied to clipboard')
  }

  const columns = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: 'Display Name',
      dataIndex: 'display_name',
      key: 'display_name',
    },
    {
      title: 'Organization',
      dataIndex: 'organization',
      key: 'organization',
    },
    {
      title: 'Client ID',
      dataIndex: 'client_id',
      key: 'client_id',
      render: (clientId: string) => (
        <Space>
          <Paragraph
            style={{ margin: 0, maxWidth: 150 }}
            ellipsis={{ tooltip: clientId }}
          >
            {clientId}
          </Paragraph>
          <Tooltip title="Copy">
            <Button
              type="text"
              size="small"
              icon={<CopyOutlined />}
              onClick={() => copyToClipboard(clientId)}
            />
          </Tooltip>
        </Space>
      ),
    },
    {
      title: 'Token Format',
      dataIndex: 'token_format',
      key: 'token_format',
    },
    {
      title: 'Expire (hours)',
      dataIndex: 'expire_in_hours',
      key: 'expire_in_hours',
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_: any, record: Application) => (
        <Space>
          <Button icon={<EditOutlined />} onClick={() => handleEdit(record)} />
          <Popconfirm
            title="Delete this application?"
            onConfirm={() => handleDelete(record.id)}
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
        <h2 className="page-title">Applications</h2>
        <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
          Add Application
        </Button>
      </div>

      <Table
        columns={columns}
        dataSource={applications}
        rowKey="id"
        loading={loading}
        pagination={{
          current: page,
          pageSize,
          total,
          onChange: (p, ps) => {
            setPage(p)
            setPageSize(ps)
          },
        }}
      />

      <Modal
        title={editingApp ? 'Edit Application' : 'Create Application'}
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => setModalOpen(false)}
        width={600}
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="owner"
            label="Owner"
            rules={[{ required: true }]}
          >
            <Input />
          </Form.Item>
          <Form.Item
            name="name"
            label="Name"
            rules={[{ required: true }]}
          >
            <Input disabled={!!editingApp} />
          </Form.Item>
          <Form.Item
            name="display_name"
            label="Display Name"
            rules={[{ required: true }]}
          >
            <Input />
          </Form.Item>
          <Form.Item
            name="organization"
            label="Organization"
            rules={[{ required: true }]}
          >
            <Input />
          </Form.Item>
          <Form.Item name="description" label="Description">
            <Input.TextArea rows={3} />
          </Form.Item>
          <Form.Item name="homepage_url" label="Homepage URL">
            <Input />
          </Form.Item>
          <Form.Item name="redirect_uris" label="Redirect URIs">
            <Input.TextArea rows={2} placeholder="One URI per line" />
          </Form.Item>
          <Form.Item name="token_format" label="Token Format">
            <Input />
          </Form.Item>
          <Form.Item name="expire_in_hours" label="Token Expiration (hours)">
            <InputNumber min={1} max={8760} style={{ width: '100%' }} />
          </Form.Item>
          {editingApp && (
            <>
              <Form.Item label="Client ID">
                <Input.Group compact>
                  <Input
                    style={{ width: 'calc(100% - 32px)' }}
                    value={editingApp.client_id}
                    readOnly
                  />
                  <Button
                    icon={<CopyOutlined />}
                    onClick={() => copyToClipboard(editingApp.client_id)}
                  />
                </Input.Group>
              </Form.Item>
              <Form.Item label="Client Secret">
                <Input.Group compact>
                  <Input.Password
                    style={{ width: 'calc(100% - 32px)' }}
                    value={editingApp.client_secret}
                    readOnly
                  />
                  <Button
                    icon={<CopyOutlined />}
                    onClick={() => copyToClipboard(editingApp.client_secret)}
                  />
                </Input.Group>
              </Form.Item>
            </>
          )}
        </Form>
      </Modal>
    </div>
  )
}
