import { useEffect, useState } from 'react'
import {
  Table,
  Button,
  Space,
  Modal,
  Form,
  Input,
  message,
  Popconfirm,
} from 'antd'
import { PlusOutlined, EditOutlined, DeleteOutlined } from '@ant-design/icons'
import { organizationsApi, Organization } from '../api/client'

export default function Organizations() {
  const [loading, setLoading] = useState(false)
  const [organizations, setOrganizations] = useState<Organization[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [modalOpen, setModalOpen] = useState(false)
  const [editingOrg, setEditingOrg] = useState<Organization | null>(null)
  const [form] = Form.useForm()

  const fetchOrganizations = async () => {
    setLoading(true)
    try {
      const res = await organizationsApi.list({ page, page_size: pageSize })
      setOrganizations(res.data.data)
      setTotal(res.data.total)
    } catch (error) {
      message.error('Failed to fetch organizations')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchOrganizations()
  }, [page, pageSize])

  const handleCreate = () => {
    setEditingOrg(null)
    form.resetFields()
    form.setFieldsValue({ owner: 'admin', password_type: 'argon2' })
    setModalOpen(true)
  }

  const handleEdit = (org: Organization) => {
    setEditingOrg(org)
    form.setFieldsValue(org)
    setModalOpen(true)
  }

  const handleDelete = async (id: string) => {
    try {
      await organizationsApi.delete(id)
      message.success('Organization deleted')
      fetchOrganizations()
    } catch (error) {
      message.error('Failed to delete organization')
    }
  }

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields()
      if (editingOrg) {
        await organizationsApi.update(editingOrg.id, values)
        message.success('Organization updated')
      } else {
        await organizationsApi.create(values)
        message.success('Organization created')
      }
      setModalOpen(false)
      fetchOrganizations()
    } catch (error: any) {
      if (error.errorFields) return
      message.error(error.response?.data?.details || 'Operation failed')
    }
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
      title: 'Owner',
      dataIndex: 'owner',
      key: 'owner',
    },
    {
      title: 'Website',
      dataIndex: 'website_url',
      key: 'website_url',
      render: (url: string) =>
        url ? (
          <a href={url} target="_blank" rel="noopener noreferrer">
            {url}
          </a>
        ) : (
          '-'
        ),
    },
    {
      title: 'Password Type',
      dataIndex: 'password_type',
      key: 'password_type',
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date: string) => new Date(date).toLocaleDateString(),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_: any, record: Organization) => (
        <Space>
          <Button icon={<EditOutlined />} onClick={() => handleEdit(record)} />
          <Popconfirm
            title="Delete this organization?"
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
        <h2 className="page-title">Organizations</h2>
        <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
          Add Organization
        </Button>
      </div>

      <Table
        columns={columns}
        dataSource={organizations}
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
        title={editingOrg ? 'Edit Organization' : 'Create Organization'}
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => setModalOpen(false)}
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
            <Input disabled={!!editingOrg} />
          </Form.Item>
          <Form.Item
            name="display_name"
            label="Display Name"
            rules={[{ required: true }]}
          >
            <Input />
          </Form.Item>
          <Form.Item name="website_url" label="Website URL">
            <Input />
          </Form.Item>
          <Form.Item name="favicon" label="Favicon URL">
            <Input />
          </Form.Item>
          <Form.Item name="password_type" label="Password Type">
            <Input />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
