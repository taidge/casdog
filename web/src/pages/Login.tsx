import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Form, Input, Button, message } from 'antd'
import { UserOutlined, LockOutlined, HomeOutlined } from '@ant-design/icons'
import { useAuth } from '../context/AuthContext'

export default function Login() {
  const [loading, setLoading] = useState(false)
  const { login } = useAuth()
  const navigate = useNavigate()

  const onFinish = async (values: { owner: string; name: string; password: string }) => {
    setLoading(true)
    try {
      await login(values)
      message.success('Login successful!')
      navigate('/')
    } catch (error: any) {
      message.error(error.response?.data?.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-title">
          <div className="login-logo">🔐</div>
          <h1>Casdog</h1>
          <p style={{ color: '#666' }}>IAM/SSO Platform</p>
        </div>
        <Form
          name="login"
          initialValues={{ owner: 'built-in', name: 'admin' }}
          onFinish={onFinish}
          size="large"
        >
          <Form.Item
            name="owner"
            rules={[{ required: true, message: 'Please input organization!' }]}
          >
            <Input prefix={<HomeOutlined />} placeholder="Organization" />
          </Form.Item>
          <Form.Item
            name="name"
            rules={[{ required: true, message: 'Please input username!' }]}
          >
            <Input prefix={<UserOutlined />} placeholder="Username" />
          </Form.Item>
          <Form.Item
            name="password"
            rules={[{ required: true, message: 'Please input password!' }]}
          >
            <Input.Password prefix={<LockOutlined />} placeholder="Password" />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} block>
              Log in
            </Button>
          </Form.Item>
          <div style={{ textAlign: 'center' }}>
            Don't have an account? <Link to="/signup">Sign up</Link>
          </div>
        </Form>
      </div>
    </div>
  )
}
