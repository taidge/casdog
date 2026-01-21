import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './context/AuthContext'
import MainLayout from './layouts/MainLayout'
import Login from './pages/Login'
import Signup from './pages/Signup'
import Dashboard from './pages/Dashboard'
import Users from './pages/Users'
import Organizations from './pages/Organizations'
import Applications from './pages/Applications'
import Roles from './pages/Roles'
import Permissions from './pages/Permissions'
import Policies from './pages/Policies'

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading } = useAuth()

  if (loading) {
    return <div>Loading...</div>
  }

  return isAuthenticated ? <>{children}</> : <Navigate to="/login" />
}

function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/signup" element={<Signup />} />
      <Route
        path="/"
        element={
          <PrivateRoute>
            <MainLayout />
          </PrivateRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="users" element={<Users />} />
        <Route path="organizations" element={<Organizations />} />
        <Route path="applications" element={<Applications />} />
        <Route path="roles" element={<Roles />} />
        <Route path="permissions" element={<Permissions />} />
        <Route path="policies" element={<Policies />} />
      </Route>
    </Routes>
  )
}

export default App
