import type { Express } from "express";
import { createServer, type Server } from "http";
import passport from "passport";
import cors from "cors";
import { storage } from "./storage";
import { setupAuth, isAuthenticated } from "./googleAuth";
import { setupGitHubAuth } from "./githubAuth";
import { adminLogin, requireAdmin, requireSuperAdmin } from "./adminAuth";
import { insertDeploymentSchema, insertTransactionSchema, insertAppSettingsSchema, insertCoinTransferSchema, insertBannedUserSchema, insertVoucherCodeSchema } from "@shared/schema";
import { sendVerificationEmail, sendWelcomeEmail, sendPasswordResetEmail } from "./emailService";
import bcrypt from "bcryptjs";
import { WebSocketServer, WebSocket } from 'ws';
import crypto from "crypto";
import multer from "multer";
import path from "path";
import fs from "fs";
import express from "express";
import { ObjectId } from "mongodb";
import { getDb } from "./db";
import { Octokit } from "@octokit/rest";

// Middleware to check if device fingerprint is banned
async function checkDeviceBan(req: any, res: any, next: any) {
  try {
    const deviceFingerprint = req.body?.deviceFingerprint || req.headers['x-device-fingerprint'];

    if (deviceFingerprint) {
      const isBanned = await storage.isDeviceFingerprintBanned(deviceFingerprint);
      if (isBanned) {
        return res.status(403).json({ 
          message: 'Access denied: Device is banned from using this service',
          code: 'DEVICE_BANNED'
        });
      }
    }

    next();
  } catch (error) {
    console.error('Error checking device ban:', error);
    next(); // Continue on error to avoid breaking the flow
  }
}

// WebSocket connections for real-time updates
const wsConnections = new Map<string, WebSocket>();
const monitoringDeployments = new Map<string, NodeJS.Timeout>();

// Chat WebSocket connections
interface ChatClient {
  ws: WebSocket;
  userId: string;
  username: string;
  isAdmin: boolean;
  role?: string;
}

const chatClients = new Map<string, ChatClient>();

// Configure multer for file uploads
const uploadDir = path.join(process.cwd(), 'uploads', 'chat-images');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const upload = multer({
  dest: uploadDir,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

// Function to broadcast to WebSocket clients
function broadcastToClients(type: string, data: any) {
  const message = JSON.stringify({ type, data, timestamp: new Date().toISOString() });
  wsConnections.forEach((ws, clientId) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(message);
    } else {
      wsConnections.delete(clientId);
    }
  });
}

// Function to broadcast to chat clients
function broadcastToChatClients(type: string, data: any, excludeClientId?: string) {
  const message = JSON.stringify({ type, ...data, timestamp: new Date().toISOString() });
  chatClients.forEach((chatClient, clientId) => {
    if (clientId !== excludeClientId && chatClient.ws.readyState === WebSocket.OPEN) {
      chatClient.ws.send(message);
    } else if (chatClient.ws.readyState !== WebSocket.OPEN) {
      chatClients.delete(clientId);
    }
  });
}

// Function to monitor workflow status for a specific branch
async function monitorWorkflowStatus(branchName: string) {
  try {
    const [githubToken, repoOwner, repoName, workflowFile] = await Promise.all([
      storage.getAppSetting('github_token'),
      storage.getAppSetting('github_repo_owner'),
      storage.getAppSetting('github_repo_name'),
      storage.getAppSetting('github_workflow_file')
    ]);

    if (!githubToken?.value || !repoOwner?.value || !repoName?.value) return;

    const GITHUB_TOKEN = githubToken.value;
    const REPO_OWNER = repoOwner.value;
    const REPO_NAME = repoName.value;
    const WORKFLOW_FILE = workflowFile?.value || 'deploy.yml';

    // Get latest workflow run for this branch
    const runsUrl = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/actions/workflows/${WORKFLOW_FILE}/runs?branch=${branchName}&per_page=1`;
    const response = await fetch(runsUrl, {
      headers: {
        'Authorization': `token ${GITHUB_TOKEN}`,
        'Accept': 'application/vnd.github.v3+json'
      }
    });

    if (response.ok) {
      const data = await response.json();
      const runs = data.workflow_runs || [];

      if (runs.length > 0) {
        const latestRun = runs[0];

        // Get live logs for this run
        const logsData = await getWorkflowRunLogs(GITHUB_TOKEN, REPO_OWNER, REPO_NAME, latestRun.id);

        // Check if npm start is detected in logs
        const isAppActive = detectAppStartInLogs(logsData);

        // Update deployment status if app becomes active
        if (isAppActive) {
          try {
            const deployment = await storage.getDeploymentByBranchName(branchName);
            if (deployment && deployment.status === 'deploying') {
              await storage.updateDeploymentStatus(deployment._id.toString(), 'active');
              console.log(`✓ Bot activity detected! Deployment status updated from deploying to active for branch ${branchName}`);
              
              // Broadcast status update to clients
              broadcastToClients('deployment_active', {
                branch: branchName,
                deploymentId: deployment._id.toString(),
                status: 'active',
                message: 'Bot is now deployed and running'
              });
            }
          } catch (error) {
            console.error(`Error updating deployment status for ${branchName}:`, error);
          }
        }

        broadcastToClients('workflow_status_update', {
          branch: branchName,
          run: {
            id: latestRun.id,
            status: latestRun.status,
            conclusion: latestRun.conclusion,
            created_at: latestRun.created_at,
            updated_at: latestRun.updated_at,
            html_url: latestRun.html_url
          },
          logs: logsData,
          isAppActive: isAppActive
        });

        // For infinite-running workflows, don't stop monitoring when complete
        // The workflow will auto-restart itself, so we continue monitoring
        if (latestRun.status === 'completed') {
          broadcastToClients('workflow_completed', {
            branch: branchName,
            conclusion: latestRun.conclusion,
            completed_at: latestRun.updated_at,
            isAppActive: isAppActive,
            autoRestarting: true
          });
          // Continue monitoring as the workflow will restart automatically
        }
      }
    }
  } catch (error) {
    console.error(`Error monitoring workflow for ${branchName}:`, error);
  }
}

// Helper function to get workflow run logs
async function getWorkflowRunLogs(token: string, owner: string, repo: string, runId: number) {
  try {
    // Get jobs for the workflow run
    const jobsUrl = `https://api.github.com/repos/${owner}/${repo}/actions/runs/${runId}/jobs`;
    const jobsResponse = await fetch(jobsUrl, {
      headers: {
        'Authorization': `token ${token}`,
        'Accept': 'application/vnd.github.v3+json'
      }
    });

    if (!jobsResponse.ok) return [];

    const jobsData = await jobsResponse.json();

    // Get logs for each job
    const logsPromises = jobsData.jobs.map(async (job: any) => {
      try {
        const logsUrl = `https://api.github.com/repos/${owner}/${repo}/actions/jobs/${job.id}/logs`;
        const logsResponse = await fetch(logsUrl, {
          headers: {
            'Authorization': `token ${token}`,
            'Accept': 'application/vnd.github.v3+json'
          }
        });

        if (logsResponse.ok) {
          const logs = await logsResponse.text();
          return { 
            jobId: job.id, 
            jobName: job.name, 
            status: job.status,
            conclusion: job.conclusion,
            logs: logs || '',
            started_at: job.started_at,
            completed_at: job.completed_at
          };
        }
        return { 
          jobId: job.id, 
          jobName: job.name, 
          status: job.status,
          conclusion: job.conclusion,
          logs: 'Logs not yet available',
          started_at: job.started_at,
          completed_at: job.completed_at
        };
      } catch (error) {
        return { 
          jobId: job.id, 
          jobName: job.name, 
          status: 'error',
          conclusion: 'error',
          logs: 'Error fetching logs',
          started_at: job.started_at,
          completed_at: job.completed_at
        };
      }
    });

    return await Promise.all(logsPromises);
  } catch (error) {
    console.error('Error fetching workflow logs:', error);
    return [];
  }
}

// Helper function to detect if app has started in logs
function detectAppStartInLogs(logsData: any[]): boolean {
  if (!logsData || logsData.length === 0) return false;

  const appStartIndicators = [
    'npm start',
    'node index.js',
    'Starting application',
    'Server is running',
    'App is listening',
    'Bot is online',
    'Connected successfully',
    'Ready to serve',
    'Application started',
    'Bot activity detected' // Added to detect the workflow log message
  ];

  for (const logEntry of logsData) {
    if (logEntry.logs) {
      const logs = logEntry.logs.toLowerCase();
      for (const indicator of appStartIndicators) {
        if (logs.includes(indicator.toLowerCase())) {
          return true;
        }
      }
    }
  }

  return false;
}

// Function to start monitoring a deployment
function startWorkflowMonitoring(branchName: string) {
  // Clear existing monitoring if any
  const existingTimeout = monitoringDeployments.get(branchName);
  if (existingTimeout) {
    clearTimeout(existingTimeout);
  }

  // Monitor every 30 seconds indefinitely for auto-restarting workflows
  let attempts = 0;
  const maxAttempts = 9999; // Effectively infinite for auto-restarting workflows

  const monitor = () => {
    if (attempts >= maxAttempts) {
      // For auto-restarting workflows, reset attempts counter instead of stopping
      attempts = 0;
      broadcastToClients('monitoring_reset', { 
        branch: branchName, 
        message: 'Monitoring reset - workflow continues auto-restarting' 
      });
    }

    monitorWorkflowStatus(branchName);
    attempts++;

    const timeoutId = setTimeout(monitor, 30000); // 30 seconds
    monitoringDeployments.set(branchName, timeoutId);
  };

  // Start monitoring immediately
  monitor();
}

export async function registerRoutes(app: Express): Promise<Server> {
  // CORS configuration for production domains
  const allowedOrigins = [
    'http://localhost:5000',
    'http://localhost:3000',
    'https://inconnu-host.onrender.com',
    process.env.REPLIT_DEV_DOMAIN ? `https://${process.env.REPLIT_DEV_DOMAIN}` : null,
  ].filter((origin): origin is string => origin !== null);

  const corsOptions = {
    origin: allowedOrigins,
    credentials: true,
    optionsSuccessStatus: 200,
  };

  app.use(cors(corsOptions));

  // Auth middleware
  await setupAuth(app);
  await setupGitHubAuth(app);

  // Maintenance mode middleware - check before all routes except maintenance and admin
  const maintenanceMiddleware = async (req: any, res: any, next: any) => {
    const url = req.originalUrl || req.url;

    // Skip maintenance check for maintenance info, admin routes, and auth routes
    if (url.startsWith('/api/maintenance') || 
        url.startsWith('/api/admin') || 
        url.startsWith('/api/auth') || 
        url.startsWith('/favicon.ico') ||
        url.includes('vite') ||
        url.includes('@')) {
      return next();
    }

    // Check if user is admin - admins can bypass maintenance mode
    const isAdmin = req.user && (req.user.isAdmin || req.user.role === 'admin' || req.user.role === 'super_admin');
    if (isAdmin) {
      return next();
    }

    try {
      const maintenanceMode = await storage.isMaintenanceModeEnabled();
      if (maintenanceMode) {
        // For API requests, return JSON response
        if (url.startsWith('/api/')) {
          return res.status(503).json({ 
            error: 'Service Unavailable', 
            message: 'Site is currently under maintenance. Please try again later.' 
          });
        }
        // For regular requests, this will be handled by the frontend router
        return next();
      }
    } catch (error) {
      console.error('Error checking maintenance mode:', error);
    }

    next();
  };

  app.use(maintenanceMiddleware);



  // User status check middleware - auto logout banned users
  const userStatusMiddleware = async (req: any, res: any, next: any) => {
    // Skip for non-authenticated endpoints and admin endpoints
    const url = req.originalUrl || req.url;
    if (!req.user || 
        url.startsWith('/api/auth') || 
        url.startsWith('/api/admin') ||
        url.startsWith('/favicon.ico') ||
        url.includes('vite') ||
        url.includes('@')) {
      return next();
    }

    try {
      // Check if user is banned or has restricted status
      const currentUser = await storage.getUser(req.user._id.toString());
      if (currentUser && (currentUser.status === 'banned' || currentUser.status === 'restricted')) {
        // Destroy session and force logout
        req.session.destroy((err: any) => {
          if (err) {
            console.error('Error destroying session:', err);
          }
        });

        // For API requests, return JSON response
        if (url.startsWith('/api/')) {
          return res.status(403).json({ 
            error: 'Account Banned', 
            message: 'Your account has been banned. Please contact support.',
            forceLogout: true
          });
        }

        // For regular requests, redirect to login
        return res.redirect('/login?error=account_banned');
      }
    } catch (error) {
      console.error('Error checking user status:', error);
    }

    next();
  };

  app.use(userStatusMiddleware);

  // Device restriction check API
  app.post('/api/auth/check-device-limit', async (req, res) => {
    try {
      const { deviceFingerprint, cookieValue } = req.body;

      if (!deviceFingerprint || !cookieValue) {
        return res.status(400).json({ 
          allowed: false, 
          reason: 'Invalid device fingerprint or cookie' 
        });
      }

      const result = await storage.checkDeviceAccountCreationLimit(deviceFingerprint, cookieValue);
      res.json(result);
    } catch (error) {
      console.error('Error checking device limit:', error);
      res.status(500).json({ 
        allowed: false, 
        reason: 'Server error checking device restrictions' 
      });
    }
  });

  // Chat API routes for unread message tracking
  app.get('/api/chat/unread-count', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const unreadCount = await storage.getUserUnreadMessageCount(userId);
      res.json({ count: unreadCount });
    } catch (error) {
      console.error('Error getting unread message count:', error);
      res.status(500).json({ error: 'Failed to get unread message count' });
    }
  });

  app.post('/api/chat/mark-all-read', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      await storage.markAllMessagesAsRead(userId);

      // Update user activity
      await storage.updateUserActivity(userId);

      res.json({ success: true });
    } catch (error) {
      console.error('Error marking messages as read:', error);
      res.status(500).json({ error: 'Failed to mark messages as read' });
    }
  });

  // Admin routes for chat cleanup and user management
  app.post('/api/admin/cleanup/inactive-users', requireSuperAdmin, async (req, res) => {
    try {
      const months = req.body.months || 3; // Default to 3 months
      const deletedCount = await storage.deleteInactiveUsers(months);

      res.json({ 
        success: true, 
        message: `Deleted ${deletedCount} inactive users (inactive for ${months} months)`,
        deletedCount 
      });
    } catch (error) {
      console.error('Error cleaning up inactive users:', error);
      res.status(500).json({ error: 'Failed to clean up inactive users' });
    }
  });

  app.post('/api/admin/cleanup/old-messages', requireSuperAdmin, async (req, res) => {
    try {
      const days = req.body.days || 30; // Default to 30 days for group messages
      const reason = req.body.reason || 'admin_cleanup';
      const deletedCount = await storage.deleteMessagesOlderThan(days, reason);

      res.json({ 
        success: true, 
        message: `Deleted ${deletedCount} messages older than ${days} days`,
        deletedCount 
      });
    } catch (error) {
      console.error('Error cleaning up old messages:', error);
      res.status(500).json({ error: 'Failed to clean up old messages' });
    }
  });

  app.get('/api/admin/cleanup/stats', requireSuperAdmin, async (req, res) => {
    try {
      const lastCleanupStats = await storage.getAppSetting('last_cleanup_stats');

      res.json({
        lastCleanupStats: lastCleanupStats?.value || '{}',
        lastCleanup: lastCleanupStats?.value ? JSON.parse(lastCleanupStats.value).lastCleanup : null
      });
    } catch (error) {
      console.error('Error getting cleanup stats:', error);
      res.status(500).json({ error: 'Failed to get cleanup statistics' });
    }
  });

  // Chat: Get unread message count
  app.get('/api/chat/unread-count', isAuthenticated, async (req, res) => {
    try {
      const userId = (req.user as any)._id;
      const unreadCount = await storage.getUserUnreadMessageCount(userId.toString());
      res.json({ count: unreadCount });
    } catch (error) {
      console.error('Error getting unread message count:', error);
      res.status(500).json({ error: 'Failed to get unread message count' });
    }
  });

  // Chat: Mark all messages as read
  app.post('/api/chat/mark-all-read', isAuthenticated, async (req, res) => {
    try {
      const userId = (req.user as any)._id;
      await storage.markAllMessagesAsRead(userId.toString());
      res.json({ success: true });
    } catch (error) {
      console.error('Error marking messages as read:', error);
      res.status(500).json({ error: 'Failed to mark messages as read' });
    }
  });

  // Google OAuth routes
  app.get('/api/auth/google', (req, res, next) => {
    // Store referral code in session if provided
    if (req.query.ref) {
      (req.session as any).referralCode = req.query.ref;
    }
    passport.authenticate('google', { 
      scope: ['profile', 'email'] 
    })(req, res, next);
  });

  app.get('/api/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login?error=auth_failed' }),
    async (req: any, res) => {
      try {
        // Handle referral code if stored in session
        if ((req.session as any).referralCode && req.user) {
          const referrer = await storage.getUserByReferralCode((req.session as any).referralCode);
          if (referrer && req.user._id.toString() !== referrer._id.toString()) {
            // Check if referral already exists to avoid duplicates
            const existingReferrals = await storage.getUserReferrals(referrer._id.toString());
            const alreadyReferred = existingReferrals.some(ref => 
              ref.referredId.toString() === req.user._id.toString()
            );

            if (!alreadyReferred) {
              // Get referral bonus from admin settings
              const referralBonusSetting = await storage.getAppSetting('referral_bonus');
              const referralBonus = parseInt(referralBonusSetting?.value) || 10;

              await storage.createReferral({
                referrerId: referrer._id.toString(),
                referredId: req.user._id.toString(),
                rewardClaimed: false,
                rewardAmount: referralBonus,
              });

              // Award referral bonus
              await storage.updateUserBalance(referrer._id.toString(), referralBonus);
              await storage.createTransaction({
                userId: referrer._id.toString(),
                type: "referral",
                amount: referralBonus,
                description: "Referral bonus for new user signup",
              });
            }
          }
          // Clear referral code from session
          delete (req.session as any).referralCode;
        }
      } catch (error) {
        console.error('Error processing Google OAuth referral:', error);
      }

      // Track user device fingerprint for login/registration
      try {
        const deviceFingerprint = (req.session as any)?.deviceFingerprint;
        if (deviceFingerprint && req.user) {
          await storage.updateUserDeviceFingerprint(req.user._id.toString(), deviceFingerprint);
        }
      } catch (error) {
        console.error('Error tracking user device fingerprint:', error);
      }

      // Successful authentication, redirect to dashboard
      res.redirect('/dashboard');
    }
  );

  // Maintenance mode routes (available to all)
  app.get('/api/maintenance/info', async (req, res) => {
    try {
      const [maintenanceMessage, estimatedTime, endTime] = await Promise.all([
        storage.getAppSetting('maintenance_message'),
        storage.getAppSetting('maintenance_estimated_time'),
        storage.getAppSetting('maintenance_end_time')
      ]);

      res.json({
        message: maintenanceMessage?.value,
        estimatedTime: estimatedTime?.value,
        endTime: endTime?.value
      });
    } catch (error) {
      console.error('Error getting maintenance info:', error);
      res.status(500).json({ error: 'Failed to get maintenance info' });
    }
  });

  // Check if site is in maintenance mode
  app.get('/api/maintenance/status', async (req, res) => {
    try {
      const isMaintenanceMode = await storage.isMaintenanceModeEnabled();
      const isAdmin = req.user && ((req.user as any).isAdmin || (req.user as any).role === 'admin' || (req.user as any).role === 'super_admin');

      res.json({ 
        maintenanceMode: isMaintenanceMode,
        canBypass: isAdmin 
      });
    } catch (error) {
      console.error('Error checking maintenance status:', error);
      res.status(500).json({ error: 'Failed to check maintenance status' });
    }
  });

  // Currency settings for users (public endpoint for authenticated users)
  app.get('/api/currency', isAuthenticated, async (req, res) => {
    try {
      const [currency, rate, symbol] = await Promise.all([
        storage.getAppSetting('currency'),
        storage.getAppSetting('currency_rate'),
        storage.getAppSetting('currency_symbol')
      ]);

      res.json({
        currency: currency?.value || 'USD',
        rate: rate?.value || 0.1,
        symbol: symbol?.value || '$'
      });
    } catch (error) {
      console.error('Error getting currency settings:', error);
      res.status(500).json({ error: 'Failed to get currency settings' });
    }
  });

  // Auth status route
  app.get('/api/auth/user', (req, res) => {
    if (req.isAuthenticated()) {
      res.json(req.user);
    } else {
      res.status(401).json({ message: 'Not authenticated' });
    }
  });

  // Logout route
  app.post('/api/auth/logout', (req, res) => {
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ message: 'Logout failed' });
      }
      res.json({ message: 'Logged out successfully' });
    });
  });

  // User account deletion route
  app.delete('/api/user/account', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      // Prevent admins from deleting their own accounts through this endpoint
      if (user.isAdmin) {
        return res.status(403).json({ 
          message: 'Admin accounts cannot be self-deleted. Please contact another admin for account removal.' 
        });
      }

      // Delete the user and all associated data
      await storage.deleteUser(userId, userId); // User deletes themselves

      // Clear the session
      req.logout((err: any) => {
        if (err) {
          console.error('Error clearing session after account deletion:', err);
        }
      });

      res.json({ 
        success: true, 
        message: 'Your account has been permanently deleted along with all associated data.' 
      });
    } catch (error) {
      console.error('Error deleting user account:', error);
      res.status(500).json({ 
        message: 'Failed to delete account. Please try again.' 
      });
    }
  });

  // User profile routes
  app.get('/api/user/profile', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      res.json({
        _id: user._id.toString(),
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        username: user.username,
        bio: user.bio,
        profilePicture: user.profilePicture,
        socialProfiles: user.socialProfiles,
        isAdmin: user.isAdmin,
        role: user.role,
        status: user.status,
        coinBalance: user.coinBalance,
        createdAt: user.createdAt.toISOString(),
        lastLogin: user.lastLogin?.toISOString(),
        preferences: user.preferences || {}
      });
    } catch (error) {
      console.error('Error fetching user profile:', error);
      res.status(500).json({ message: 'Failed to fetch profile' });
    }
  });

  app.put('/api/user/profile', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const { firstName, lastName, username, bio, profilePicture, socialProfiles } = req.body;

      if (!firstName || !lastName) {
        return res.status(400).json({ message: 'First name and last name are required' });
      }

      await storage.updateUserProfile(userId, {
        firstName,
        lastName,
        username: username || '',
        bio: bio || '',
        profilePicture: profilePicture || '',
        socialProfiles: socialProfiles || {}
      });

      res.json({ message: 'Profile updated successfully' });
    } catch (error) {
      console.error('Error updating user profile:', error);
      res.status(500).json({ message: 'Failed to update profile' });
    }
  });

  app.put('/api/user/preferences', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const preferences = req.body;

      await storage.updateUserPreferences(userId, preferences);
      res.json({ message: 'Preferences updated successfully' });
    } catch (error) {
      console.error('Error updating user preferences:', error);
      res.status(500).json({ message: 'Failed to update preferences' });
    }
  });

  // User password change endpoint
  app.post('/api/user/change-password', isAuthenticated, async (req: any, res) => {
    try {
      const { currentPassword, newPassword } = req.body;
      const userId = req.user._id.toString();

      if (!currentPassword || !newPassword) {
        return res.status(400).json({ message: 'Current password and new password are required' });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({ message: 'New password must be at least 6 characters long' });
      }

      await storage.changeUserPassword(userId, currentPassword, newPassword);
      res.json({ message: 'Password changed successfully' });
    } catch (error: any) {
      console.error('Error changing password:', error);
      if (error.message.includes('not available for this account type')) {
        return res.status(400).json({ message: 'Password change is not available for Google OAuth accounts' });
      }
      if (error.message.includes('Current password is incorrect')) {
        return res.status(400).json({ message: 'Current password is incorrect' });
      }
      res.status(500).json({ message: 'Failed to change password' });
    }
  });

  // Link GitHub account
  app.post('/api/user/link-github', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const { githubId, githubUsername, githubProfileUrl } = req.body;

      if (!githubId || !githubUsername) {
        return res.status(400).json({ message: 'GitHub ID and username are required' });
      }

      // Check if GitHub account is already linked to another user
      const existingUser = await storage.getUserByGitHubId(githubId);
      if (existingUser && existingUser._id.toString() !== userId) {
        return res.status(400).json({ message: 'This GitHub account is already linked to another user' });
      }

      await storage.linkGitHubAccount(userId, { githubId, githubUsername, githubProfileUrl });
      res.json({ message: 'GitHub account linked successfully' });
    } catch (error) {
      console.error('Error linking GitHub account:', error);
      res.status(500).json({ message: 'Failed to link GitHub account' });
    }
  });

  // Unlink GitHub account
  app.post('/api/user/unlink-github', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      await storage.unlinkGitHubAccount(userId);
      res.json({ message: 'GitHub account unlinked successfully' });
    } catch (error) {
      console.error('Error unlinking GitHub account:', error);
      res.status(500).json({ message: 'Failed to unlink GitHub account' });
    }
  });

  // Acknowledge GitHub Actions notice
  app.post('/api/user/acknowledge-github-actions', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const db = getDb();
      await db.collection('users').updateOne(
        { _id: new ObjectId(userId) },
        { $set: { hasSeenGitHubActionsNotice: true } }
      );
      res.json({ message: 'Notice acknowledged successfully' });
    } catch (error) {
      console.error('Error acknowledging GitHub Actions notice:', error);
      res.status(500).json({ message: 'Failed to acknowledge notice' });
    }
  });

  // Get user's repositories
  app.get('/api/github/repositories', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const repositories = await storage.getUserRepositories(userId);

      // Remove sensitive token field before sending to client
      const sanitizedRepositories = repositories.map(repo => ({
        _id: repo._id,
        userId: repo.userId,
        name: repo.name,
        githubUsername: repo.githubUsername,
        repositoryName: repo.repositoryName,
        workflowName: repo.workflowName,
        branches: repo.branches,
        createdAt: repo.createdAt,
        updatedAt: repo.updatedAt
      }));

      res.json(sanitizedRepositories);
    } catch (error) {
      console.error('Error fetching repositories:', error);
      res.status(500).json({ message: 'Failed to fetch repositories' });
    }
  });

  // Create a new repository
  app.post('/api/github/repositories', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const { name, githubUsername, repositoryName, token, workflowName } = req.body;

      if (!name || !githubUsername || !repositoryName || !token || !workflowName) {
        return res.status(400).json({ message: 'All fields are required' });
      }

      const repository = await storage.createRepository({
        userId,
        name,
        githubUsername,
        repositoryName,
        token,
        workflowName,
        branches: []
      });

      // Remove sensitive token field before sending to client
      const sanitizedRepository = {
        _id: repository._id,
        userId: repository.userId,
        name: repository.name,
        githubUsername: repository.githubUsername,
        repositoryName: repository.repositoryName,
        workflowName: repository.workflowName,
        branches: repository.branches,
        createdAt: repository.createdAt,
        updatedAt: repository.updatedAt
      };

      res.json(sanitizedRepository);
    } catch (error) {
      console.error('Error creating repository:', error);
      res.status(500).json({ message: 'Failed to create repository' });
    }
  });

  // Check username availability route
  app.post('/api/auth/check-username', async (req, res) => {
    try {
      const { username } = req.body;

      if (!username) {
        return res.status(400).json({ message: 'Username is required' });
      }

      if (username.length < 3 || username.length > 20) {
        return res.status(400).json({ 
          available: false,
          message: 'Username must be between 3 and 20 characters' 
        });
      }

      if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        return res.status(400).json({ 
          available: false,
          message: 'Username can only contain letters, numbers, and underscores' 
        });
      }

      const isAvailable = await storage.checkUsernameAvailability(username);

      res.json({
        available: isAvailable,
        message: isAvailable ? 'Username is available' : 'Username is already taken'
      });
    } catch (error) {
      console.error('Error checking username availability:', error);
      res.status(500).json({ message: 'Error checking username availability' });
    }
  });

  // Check device limit route
  app.post('/api/auth/check-device-limit', async (req, res) => {
    try {
      const { deviceFingerprint } = req.body;

      if (!deviceFingerprint) {
        return res.status(400).json({ message: 'Device fingerprint is required' });
      }

      const deviceLimit = await storage.checkDeviceAccountLimit(deviceFingerprint);
      res.json(deviceLimit);
    } catch (error) {
      console.error('Error checking device limit:', error);
      res.status(500).json({ message: 'Error checking device limit' });
    }
  });

  // Local email signup route
  app.post('/api/auth/local/signup', async (req, res) => {
    try {
      const { firstName, lastName, username, email, password, referralCode } = req.body;

      // Validate required fields
      if (!firstName || !lastName || !username || !email || !password) {
        return res.status(400).json({ message: 'All fields are required' });
      }

      // Check username availability
      const isUsernameAvailable = await storage.checkUsernameAvailability(username);
      if (!isUsernameAvailable) {
        return res.status(400).json({ message: 'Username is already taken' });
      }

      // Check if user already exists
      const existingUser = await storage.getUserByEmail(email);
      if (existingUser) {
        return res.status(400).json({ message: 'User with this email already exists' });
      }

      // Get device fingerprint for registration tracking and duplicate account prevention
      const { deviceFingerprint } = req.body;

      // Check for existing accounts from same device fingerprint
      if (deviceFingerprint) {
        const existingAccountsFromDevice = await storage.getUsersByDeviceFingerprint(deviceFingerprint);

        // Get configurable max accounts per device from admin settings (default to 1)
        const maxAccountsSetting = await storage.getAppSetting('max_accounts_per_device');
        const maxAccountsPerDevice = maxAccountsSetting?.value || 1;

        const activeAccounts = existingAccountsFromDevice.filter(user => 
          user.status !== 'banned' && user.status !== 'restricted'
        );

        if (activeAccounts.length >= maxAccountsPerDevice) {
          return res.status(400).json({ 
            message: `Only 1 account allowed per device. Contact support if you believe this is an error.`
          });
        }
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Generate verification token
      const verificationToken = crypto.randomBytes(32).toString('hex');
      const verificationTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      // Create user with unverified status
      const newUser = await storage.createLocalUser({
        firstName,
        lastName,
        username,
        email,
        password: hashedPassword,
        verificationToken,
        verificationTokenExpiry,
        isVerified: false,
        referralCode: referralCode || undefined,
        deviceFingerprint: deviceFingerprint,
        deviceHistory: deviceFingerprint ? [deviceFingerprint] : [],
      });

      // Send verification email with dynamic URL from request
      const protocol = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
      const host = req.get('host') || req.headers['x-forwarded-host'] || 'localhost:5000';
      const baseUrl = `${protocol}://${host}`;

      const emailSent = await sendVerificationEmail(email, verificationToken, baseUrl);

      if (!emailSent) {
        console.error('Failed to send verification email');
        // Continue anyway, user can request resend
      }

      res.status(201).json({ 
        message: 'Account created successfully. Please check your email to verify your account.',
        userId: newUser.insertedId,
      });
    } catch (error) {
      console.error('Signup error:', error);
      res.status(500).json({ message: 'Failed to create account' });
    }
  });

  // Email verification route
  app.get('/api/auth/verify-email', async (req, res) => {
    try {
      const { token } = req.query;

      if (!token) {
        return res.status(400).json({ message: 'Verification token is required' });
      }

      const user = await storage.getUserByVerificationToken(token as string);

      if (!user) {
        return res.status(400).json({ message: 'Invalid or expired verification token' });
      }

      if (user.verificationTokenExpiry && new Date() > user.verificationTokenExpiry) {
        return res.status(400).json({ message: 'Verification token has expired' });
      }

      // Verify the user
      await storage.verifyUser(user._id.toString());

      // Send welcome email with dynamic URL
      const protocol = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
      const host = req.get('host') || req.headers['x-forwarded-host'] || 'localhost:5000';
      const baseUrl = `${protocol}://${host}`;

      await sendWelcomeEmail(user.email, user.firstName, baseUrl);

      res.json({ message: 'Email verified successfully. You can now sign in.' });
    } catch (error) {
      console.error('Email verification error:', error);
      res.status(500).json({ message: 'Email verification failed' });
    }
  });

  // Local email login route
  app.post('/api/auth/local/login', async (req, res) => {
    try {
      const { emailOrUsername, password } = req.body;

      if (!emailOrUsername || !password) {
        return res.status(400).json({ message: 'Email/username and password are required' });
      }

      const user = await storage.getUserByEmailOrUsername(emailOrUsername);

      if (!user || !user.password) {
        return res.status(401).json({ message: 'Invalid email/username or password' });
      }

      if (!user.isVerified) {
        return res.status(401).json({ message: 'Please verify your email before signing in' });
      }

      const isValidPassword = await bcrypt.compare(password, user.password);

      if (!isValidPassword) {
        return res.status(401).json({ message: 'Invalid email/username or password' });
      }

      // Log the user in using passport session
      req.login(user, async (err) => {
        if (err) {
          console.error('Login error:', err);
          return res.status(500).json({ message: 'Login failed' });
        }

        // Track user device fingerprint and create login history
        try {
          const { deviceFingerprint } = req.body;
          const ipAddress = req.ip || req.connection.remoteAddress || 'unknown';
          const userAgent = req.get('User-Agent') || 'unknown';

          if (deviceFingerprint) {
            await storage.updateUserDeviceFingerprint(user._id.toString(), deviceFingerprint);
          }

          // Create login history entry
          await storage.createLoginHistory({
            userId: user._id.toString(),
            email: user.email,
            username: user.username,
            ipAddress,
            userAgent,
            deviceFingerprint,
            loginMethod: 'local',
            success: true,
          });

          // Update last login time
          await storage.updateUserLastLogin(user._id.toString(), ipAddress);
        } catch (error) {
          console.error('Error tracking user device fingerprint and login history:', error);
        }

        res.json({ message: 'Login successful', user: { _id: user._id, email: user.email, firstName: user.firstName, lastName: user.lastName, username: user.username } });
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ message: 'Login failed' });
    }
  });

  // Forgot password route
  app.post('/api/auth/forgot-password', async (req, res) => {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ message: 'Email is required' });
      }

      const user = await storage.getUserByEmail(email);

      if (!user) {
        // Return success even if user not found for security reasons
        return res.json({ message: 'If an account with that email exists, we have sent password reset instructions.' });
      }

      if (user.authProvider !== 'local') {
        return res.status(400).json({ message: 'Password reset is only available for email/password accounts. Please sign in with Google instead.' });
      }

      // Generate reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      // Save reset token to database
      await storage.setPasswordResetToken(email, resetToken, resetExpiry);

      // Send password reset email
      const protocol = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
      const host = req.get('host') || req.headers['x-forwarded-host'] || 'localhost:5000';
      const baseUrl = `${protocol}://${host}`;

      const emailSent = await sendPasswordResetEmail(email, resetToken, baseUrl);

      if (!emailSent) {
        console.error('Failed to send password reset email');
        return res.status(500).json({ message: 'Failed to send password reset email. Please try again.' });
      }

      res.json({ message: 'If an account with that email exists, we have sent password reset instructions.' });
    } catch (error) {
      console.error('Forgot password error:', error);
      res.status(500).json({ message: 'Failed to process password reset request' });
    }
  });

  // Reset password route
  app.post('/api/auth/reset-password', async (req, res) => {
    try {
      const { token, newPassword } = req.body;

      if (!token || !newPassword) {
        return res.status(400).json({ message: 'Reset token and new password are required' });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({ message: 'Password must be at least 6 characters long' });
      }

      const user = await storage.getUserByResetToken(token);

      if (!user) {
        return res.status(400).json({ message: 'Invalid or expired reset token' });
      }

      if (user.resetPasswordExpiry && new Date() > user.resetPasswordExpiry) {
        return res.status(400).json({ message: 'Reset token has expired' });
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update password and clear reset token
      await storage.resetPassword(user._id.toString(), hashedPassword);

      res.json({ message: 'Password reset successfully. You can now sign in with your new password.' });
    } catch (error) {
      console.error('Reset password error:', error);
      res.status(500).json({ message: 'Failed to reset password' });
    }
  });

  // Resend verification email route
  app.post('/api/auth/resend-verification', async (req, res) => {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ message: 'Email is required' });
      }

      const user = await storage.getUserByEmail(email);

      if (!user) {
        return res.status(404).json({ message: 'No account found with this email address' });
      }

      if (user.authProvider !== 'local') {
        return res.status(400).json({ message: 'Email verification is only required for email/password accounts' });
      }

      if (user.isVerified) {
        return res.status(400).json({ message: 'This email address is already verified' });
      }

      // Generate new verification token
      const verificationToken = crypto.randomBytes(32).toString('hex');
      const verificationTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      // Update verification token in database
      await storage.updateVerificationToken(email, verificationToken, verificationTokenExpiry);

      // Send verification email
      const protocol = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
      const host = req.get('host') || req.headers['x-forwarded-host'] || 'localhost:5000';
      const baseUrl = `${protocol}://${host}`;

      const emailSent = await sendVerificationEmail(email, verificationToken, baseUrl);

      if (!emailSent) {
        console.error('Failed to resend verification email');
        return res.status(500).json({ message: 'Failed to send verification email. Please try again.' });
      }

      res.json({ message: 'Verification email has been sent. Please check your inbox and spam folder.' });
    } catch (error) {
      console.error('Resend verification error:', error);
      res.status(500).json({ message: 'Failed to resend verification email' });
    }
  });

  // Check username availability
  app.post('/api/auth/check-username', async (req, res) => {
    try {
      const { username } = req.body;

      if (!username) {
        return res.status(400).json({ message: 'Username is required' });
      }

      if (username.length < 3 || username.length > 20) {
        return res.status(400).json({ 
          available: false, 
          message: 'Username must be between 3 and 20 characters' 
        });
      }

      // Check if username contains only valid characters (alphanumeric and underscore)
      if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        return res.status(400).json({ 
          available: false, 
          message: 'Username can only contain letters, numbers, and underscores' 
        });
      }

      const isAvailable = await storage.checkUsernameAvailability(username);
      res.json({ available: isAvailable });
    } catch (error) {
      console.error('Error checking username availability:', error);
      res.status(500).json({ message: 'Failed to check username availability' });
    }
  });

  // Check device account limit
  app.post('/api/auth/check-device-limit', async (req, res) => {
    try {
      const { deviceFingerprint } = req.body;

      if (!deviceFingerprint) {
        return res.status(400).json({ message: 'Device fingerprint is required' });
      }

      const deviceLimit = await storage.checkDeviceAccountLimit(deviceFingerprint);
      res.json(deviceLimit);
    } catch (error) {
      console.error('Error checking device limit:', error);
      res.status(500).json({ message: 'Failed to check device limit' });
    }
  });

  // Get user login history
  app.get('/api/auth/login-history', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const limit = parseInt(req.query.limit as string) || 50;

      const loginHistory = await storage.getUserLoginHistory(userId, limit);
      res.json({ loginHistory });
    } catch (error) {
      console.error('Error fetching login history:', error);
      res.status(500).json({ message: 'Failed to fetch login history' });
    }
  });

  // Check branch name availability (GET for frontend compatibility)
  app.get('/api/deployments/check-branch', isAuthenticated, async (req: any, res) => {
    try {
      const { branchName } = req.query;
      const userId = req.user._id.toString();

      if (!branchName) {
        return res.status(400).json({ message: 'Branch name is required' });
      }

      if (branchName.length < 2 || branchName.length > 50) {
        return res.status(400).json({ 
          available: false, 
          message: 'Branch name must be between 2 and 50 characters' 
        });
      }

      // Check if branch name contains only valid characters
      if (!/^[a-zA-Z0-9_-]+$/.test(branchName)) {
        return res.status(400).json({ 
          available: false, 
          message: 'Branch name can only contain letters, numbers, hyphens, and underscores' 
        });
      }

      const isAvailable = await storage.checkBranchNameAvailability(branchName, userId);
      res.json({ available: isAvailable });
    } catch (error) {
      console.error('Error checking branch name availability:', error);
      res.status(500).json({ message: 'Error checking availability' });
    }
  });

  // Also support POST for backward compatibility
  app.post('/api/deployments/check-branch', isAuthenticated, async (req: any, res) => {
    try {
      const { branchName } = req.body;
      const userId = req.user._id.toString();

      if (!branchName) {
        return res.status(400).json({ message: 'Branch name is required' });
      }

      if (branchName.length < 2 || branchName.length > 50) {
        return res.status(400).json({ 
          available: false, 
          message: 'Branch name must be between 2 and 50 characters' 
        });
      }

      // Check if branch name contains only valid characters
      if (!/^[a-zA-Z0-9_-]+$/.test(branchName)) {
        return res.status(400).json({ 
          available: false, 
          message: 'Branch name can only contain letters, numbers, hyphens, and underscores' 
        });
      }

      const isAvailable = await storage.checkBranchNameAvailability(branchName, userId);
      res.json({ available: isAvailable });
    } catch (error) {
      console.error('Error checking branch name availability:', error);
      res.status(500).json({ message: 'Error checking availability' });
    }
  });

  // Get developer info (for public display)
  app.get('/api/developer-info', async (req, res) => {
    try {
      const developerInfo = await storage.getDeveloperInfo();
      res.json({ developerInfo });
    } catch (error) {
      console.error('Error fetching developer info:', error);
      res.status(500).json({ message: 'Failed to fetch developer info' });
    }
  });

  // Set developer info (admin only)
  app.post('/api/admin/developer-info', requireAdmin, async (req: any, res) => {
    try {
      const { name, appName, channels } = req.body;

      if (!name) {
        return res.status(400).json({ message: 'Developer name is required' });
      }

      const developerInfo = await storage.setDeveloperInfo({
        name,
        appName,
        channels: channels || {},
        isActive: true,
      });

      res.json({ developerInfo });
    } catch (error) {
      console.error('Error setting developer info:', error);
      res.status(500).json({ message: 'Failed to set developer info' });
    }
  });

  // Update developer info (admin only)
  app.put('/api/admin/developer-info/:id', requireAdmin, async (req: any, res) => {
    try {
      const { id } = req.params;
      const updates = req.body;

      await storage.updateDeveloperInfo(id, updates);
      res.json({ message: 'Developer info updated successfully' });
    } catch (error) {
      console.error('Error updating developer info:', error);
      res.status(500).json({ message: 'Failed to update developer info' });
    }
  });

  // Get any user's profile by ID (for profile modal)
  app.get('/api/user/profile/:userId', isAuthenticated, async (req: any, res) => {
    try {
      const { userId } = req.params;
      const user = await storage.getUserProfileById(userId);

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      // Return public profile information
      const publicProfile = {
        _id: user._id.toString(),
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        username: user.username,
        bio: user.bio,
        profilePicture: user.profilePicture,
        socialProfiles: user.socialProfiles,
        isAdmin: user.isAdmin,
        role: user.role,
        status: user.status,
        createdAt: user.createdAt.toISOString(),
        lastLogin: user.lastLogin?.toISOString()
      };

      res.json(publicProfile);
    } catch (error) {
      console.error('Error fetching user profile:', error);
      res.status(500).json({ message: 'Failed to fetch user profile' });
    }
  });

  // Dashboard stats
  app.get('/api/dashboard/stats', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const user = await storage.getUser(userId);
      const deploymentStats = await storage.getDeploymentStats(userId);
      const referralStats = await storage.getReferralStats(userId);

      res.json({
        coinBalance: user?.coinBalance || 0,
        ...deploymentStats,
        ...referralStats,
      });
    } catch (error) {
      console.error("Error fetching dashboard stats:", error);
      res.status(500).json({ message: "Failed to fetch dashboard stats" });
    }
  });

  // Recent activity
  app.get('/api/dashboard/activity', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const transactions = await storage.getUserTransactions(userId, 10);
      res.json(transactions);
    } catch (error) {
      console.error("Error fetching activity:", error);
      res.status(500).json({ message: "Failed to fetch activity" });
    }
  });

  // Check GitHub connection and fork status
  app.get('/api/github/connection-status', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      const status = {
        connected: false,
        username: null as string | null,
        hasValidToken: false,
        hasFork: false,
        forkUrl: null as string | null,
        error: null as string | null
      };

      // Check if GitHub is connected
      if (!user.githubAccessToken || !user.githubUsername) {
        return res.json(status);
      }

      status.connected = true;
      status.username = user.githubUsername;

      // Test token validity by making a simple API call
      try {
        const userResponse = await fetch('https://api.github.com/user', {
          headers: {
            'Authorization': `token ${user.githubAccessToken}`,
            'Accept': 'application/vnd.github.v3+json'
          }
        });

        if (userResponse.ok) {
          status.hasValidToken = true;

          // Check if user has forked the repo
          const repoResponse = await fetch(`https://api.github.com/repos/${user.githubUsername}/subzero-md`, {
            headers: {
              'Authorization': `token ${user.githubAccessToken}`,
              'Accept': 'application/vnd.github.v3+json'
            }
          });

          if (repoResponse.ok) {
            status.hasFork = true;
            status.forkUrl = `https://github.com/${user.githubUsername}/subzero-md`;
          }
        } else if (userResponse.status === 401) {
          status.error = 'GitHub token is invalid or expired. Please reconnect your GitHub account.';
        } else {
          status.error = `GitHub API error: ${userResponse.statusText}`;
        }
      } catch (error) {
        status.error = error instanceof Error ? error.message : 'Failed to verify GitHub connection';
      }

      res.json(status);
    } catch (error) {
      console.error("Error checking GitHub status:", error);
      res.status(500).json({ message: "Failed to check GitHub status" });
    }
  });

  // Deployments
  app.get('/api/deployments', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const deployments = await storage.getUserDeployments(userId);
      res.json(deployments);
    } catch (error) {
      console.error("Error fetching deployments:", error);
      res.status(500).json({ message: "Failed to fetch deployments" });
    }
  });

  // User GitHub deployment - uses user's connected GitHub account
  app.post('/api/deployments/github', checkDeviceBan, isAuthenticated, async (req: any, res) => {
    console.log('=== USER GITHUB DEPLOYMENT STARTED ===');
    try {
      const userId = req.user._id.toString();
      console.log('User ID:', userId);
      const user = await storage.getUser(userId);

      if (!user) {
        console.error('User not found:', userId);
        return res.status(404).json({ message: "User not found" });
      }

      console.log('User:', { 
        username: user.username, 
        githubUsername: user.githubUsername,
        hasGithubToken: !!user.githubAccessToken 
      });

      // Check if user has GitHub connected
      if (!user.githubAccessToken || !user.githubUsername) {
        console.error('GitHub not connected for user:', user.username);
        return res.status(400).json({ 
          message: 'Please connect your GitHub account first',
          requiresGitHub: true
        });
      }

      const { branchName, sessionId, ownerNumber, prefix } = req.body;
      console.log('Deployment request:', { repositoryId: null, branchName, sessionId, ownerNumber, prefix }); // repositoryId is not used here

      if (!branchName || !sessionId || !ownerNumber || !prefix) {
        console.error('Missing required fields');
        return res.status(400).json({ message: 'All fields are required' });
      }

      // Get deployment cost setting
      const deploymentFeeSetting = await storage.getAppSetting('deployment_fee');
      const deploymentFee = parseInt(deploymentFeeSetting?.value) || 10;

      // Check user's wallet balance
      const userBalance = user.coinBalance || 0;

      if (userBalance < deploymentFee) {
        return res.status(400).json({ 
          message: `Insufficient coins. You need ${deploymentFee} coins to deploy this bot. You currently have ${userBalance} coins.`,
          required: deploymentFee,
          current: userBalance,
          shortfall: deploymentFee - userBalance
        });
      }

      const deploymentNumber = await storage.getNextDeploymentNumber(userId);

      // Use user's own GitHub credentials and the default repo
      const GITHUB_TOKEN = user.githubAccessToken;
      const REPO_OWNER = user.githubUsername;
      const REPO_NAME = 'subzero-md'; // Hardcoded to user's fork
      const MAIN_BRANCH = 'main';
      const WORKFLOW_FILE = 'deploy.yml'; // Hardcoded workflow file

      // Sanitize branch name
      const sanitizeBranchName = (name: string) => {
        return name
          .replace(/[^a-zA-Z0-9._-]/g, '-')
          .replace(/^\.+|\.+$/g, '')
          .replace(/\.\.+/g, '.')
          .replace(/^-+|-+$/g, '')
          .replace(/--+/g, '-')
          .substring(0, 250);
      };

      let sanitizedBranchName = sanitizeBranchName(branchName.trim());
      if (!sanitizedBranchName) {
        return res.status(400).json({ message: 'Invalid branch name. Please provide a valid app name.' });
      }

      // Deduct coins first
      await storage.updateUserBalance(userId, -deploymentFee);

      // GitHub API helper for user's repo
      const makeUserGitHubRequest = async (method: string, endpoint: string, data: any = null) => {
        const url = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/${endpoint}`;
        const config: any = {
          method,
          headers: {
            'Authorization': `token ${GITHUB_TOKEN}`,
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'SUBZERO-Deploy'
          }
        };
        if (data) {
          config.body = JSON.stringify(data);
          config.headers['Content-Type'] = 'application/json';
        }

        const response = await fetch(url, config);
        if (!response.ok) {
          const errorText = await response.text();
          console.error(`GitHub API Error:`, {
            url,
            status: response.status,
            statusText: response.statusText,
            errorText
          });
          throw new Error(`GitHub API error: ${response.status} ${response.statusText} - ${errorText}`);
        }

        if (response.status === 204) {
          return {};
        }

        return await response.json();
      };

      try {
        // Check if fork exists, if not fork it
        console.log('Checking if fork exists...');
        try {
          await fetch(`https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}`, {
            headers: {
              'Authorization': `token ${GITHUB_TOKEN}`,
              'Accept': 'application/vnd.github.v3+json'
            }
          }).then(async (res) => {
            if (!res.ok) throw new Error('Repo not found');
          });
          console.log(`✓ Fork already exists for ${REPO_OWNER}/${REPO_NAME}`);
        } catch {
          console.log(`⚠ Forking repo for ${REPO_OWNER}...`);
          const forkResponse = await fetch('https://api.github.com/repos/mrfrankofcc/subzero-md/forks', {
            method: 'POST',
            headers: {
              'Authorization': `token ${GITHUB_TOKEN}`,
              'Accept': 'application/vnd.github.v3+json',
              'User-Agent': 'SUBZERO-Deploy'
            }
          });

          if (!forkResponse.ok) {
            const errorText = await forkResponse.text();
            console.error('Fork failed:', errorText);
            throw new Error(`Failed to fork repository: ${forkResponse.statusText}`);
          }

          console.log('✓ Fork created successfully');
          // Wait for fork to be ready
          await new Promise(resolve => setTimeout(resolve, 5000));

          // Automatically enable GitHub Actions on the newly forked repository
          console.log('Enabling GitHub Actions on forked repository...');
          try {
            const enableActionsResponse = await fetch(`https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/actions/permissions`, {
              method: 'PUT',
              headers: {
                'Authorization': `token ${GITHUB_TOKEN}`,
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28'
              },
              body: JSON.stringify({
                enabled: true,
                allowed_actions: 'all'
              })
            });

            if (enableActionsResponse.ok || enableActionsResponse.status === 204) {
              console.log('✓ GitHub Actions automatically enabled on forked repository');
            } else {
              const errorText = await enableActionsResponse.text();
              console.warn(`Warning: Could not auto-enable GitHub Actions on fork (${enableActionsResponse.status}):`, errorText);
            }
          } catch (actionsError) {
            console.warn('Warning: Could not auto-enable GitHub Actions on fork:', actionsError);
          }
        }

        // Check if branch already exists
        console.log(`Checking if branch '${sanitizedBranchName}' exists...`);
        try {
          await makeUserGitHubRequest('GET', `git/refs/heads/${sanitizedBranchName}`);
          console.error(`Branch '${sanitizedBranchName}' already exists`);
          return res.status(400).json({ 
            message: `Branch name '${sanitizedBranchName}' is already taken. Please choose a different name.` 
          });
        } catch (error) {
          console.log('✓ Branch name available');
        }

        // Get main branch SHA
        console.log('Getting main branch SHA...');
        const mainBranchData = await makeUserGitHubRequest('GET', `git/refs/heads/${MAIN_BRANCH}`);
        const mainSha = mainBranchData.object.sha;
        console.log('✓ Main branch SHA:', mainSha);

        // Create new branch
        console.log(`Creating branch '${sanitizedBranchName}'...`);
        await makeUserGitHubRequest('POST', 'git/refs', {
          ref: `refs/heads/${sanitizedBranchName}`,
          sha: mainSha
        });
        console.log('✓ Branch created successfully');

        // Wait for GitHub to process branch creation
        await new Promise(resolve => setTimeout(resolve, 3000));

        // Update settings.js
        console.log('Updating settings.js...');
        const fileData = await makeUserGitHubRequest('GET', `contents/settings.js?ref=${sanitizedBranchName}`);
        const newContent = `module.exports = {
  SESSION_ID: "${sessionId}",
  OWNER_NUMBER: "${ownerNumber}", 
  PREFIX: "${prefix}",
  CDN: "https://mrfrankk-cdn.hf.space"
};`;

        await makeUserGitHubRequest('PUT', 'contents/settings.js', {
          message: `Update settings.js for ${sanitizedBranchName}`,
          content: Buffer.from(newContent).toString('base64'),
          sha: fileData.sha,
          branch: sanitizedBranchName
        });
        console.log('✓ settings.js updated');

        // Wait for GitHub to process file update
        await new Promise(resolve => setTimeout(resolve, 2000));

        // Enable GitHub Actions for the fork if not already enabled
        console.log('Ensuring GitHub Actions is enabled...');
        try {
          // Enable Actions on the repository
          const actionsPermUrl = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/actions/permissions`;
          const actionsResponse = await fetch(actionsPermUrl, {
            method: 'PUT',
            headers: {
              'Authorization': `token ${GITHUB_TOKEN}`,
              'Accept': 'application/vnd.github+json',
              'X-GitHub-Api-Version': '2022-11-28'
            },
            body: JSON.stringify({
              enabled: true
            })
          });

          if (actionsResponse.ok || actionsResponse.status === 204) {
            console.log('✓ GitHub Actions enabled successfully');
          } else {
            const errorText = await actionsResponse.text();
            console.warn(`Warning: Could not auto-enable GitHub Actions (${actionsResponse.status}):`, errorText);
          }
        } catch (actionsError) {
          console.warn('Warning: Could not auto-enable GitHub Actions:', actionsError);
          // Continue anyway - user might need to enable manually
        }

        // Create/update workflow file with the new workflow content
        console.log('Creating/updating workflow file...');


   /* const workflowContent = `name: SUBZERO-MD-DEPLOY
on:
  workflow_dispatch:
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '20'

      - name: Debug Environment
        run: |
          echo "=== ENVIRONMENT DEBUG ==="
          echo "Node version: \\$(node --version)"
          echo "NPM version: \\$(npm --version)"
          echo "Working directory: \\$(pwd)"
          echo "Files in current directory:"
          ls -la
          echo "=== SESSION ID CHECK ==="
          if [ -f ".env" ]; then
            echo ".env file found:"
            cat .env
          else
            echo "No .env file found"
          fi
          echo "=== CONFIG FILE CHECK ==="
          if [ -f "settings.js" ]; then
            echo "settings.js content:"
            cat settings.js
          else
            echo "No settings.js found"
          fi

      - name: Install Dependencies
        run: |
          echo "=== INSTALLING DEPENDENCIES ==="
          npm install --verbose
          echo "=== DEPENDENCY TREE ==="
          npm list --depth=0

      - name: Pre-run Checks
        run: |
          echo "=== PRE-RUN CHECKS ==="
          echo "Checking package.json scripts:"
          cat package.json | grep -A 10 '"scripts"'
          echo "=== CHECKING FOR MAIN FILES ==="
          if [ -f "index.js" ]; then echo "✓ index.js found"; else echo "✗ index.js missing"; fi

      - name: Run Bot with Detailed Logging
        run: |
          echo "=== STARTING SUBZERO-MD BOT ==="
          echo "Timestamp: \\$(date)"
          echo "Starting bot with detailed logging..."

          timeout 18000 bash -c '
            attempt=1
            while true; do
              echo "=== ATTEMPT #\\$attempt ==="
              echo ">>> Starting bot attempt #\\$attempt at \\$(date)"
              npm start 2>&1 | while IFS= read -r line; do
                echo "[\\$(date +"%H:%M:%S")] \\$line"
              done
              exit_code=\\$?
              echo ">>> Bot stopped with exit code: \\$exit_code at \\$(date)"

              if [ \\$exit_code -eq 0 ]; then
                echo "Bot exited normally, restarting in 5 seconds..."
                sleep 5
              else
                echo "Bot crashed, analyzing error and restarting in 10 seconds..."
                echo "=== ERROR ANALYSIS ==="
                echo "Checking system resources:"
                free -h
                df -h
                echo "Recent system messages:"
                dmesg | tail -5 2>/dev/null || echo "No system messages available"
                sleep 10
              fi

              attempt=\\$((attempt + 1))
            done
          ' || echo "Timeout reached after 5 hours"

      - name: Post-Run Analysis
        if: always()
        run: |
          echo "=== POST-RUN ANALYSIS ==="
          echo "Final timestamp: \\$(date)"
          echo "Checking for any log files:"
          find . -name "*.log" -type f 2>/dev/null || echo "No log files found"
          echo "=== FINAL SYSTEM STATE ==="
          free -h
          df -h

      - name: Re-Trigger Workflow
        if: always()
        run: |
          echo "=== AUTO-RESTART ==="
          echo "Preparing to restart workflow at \\$(date)"
          sleep 30
          curl -X POST \\\\
            -H "Authorization: Bearer \\$\{{ secrets.GITHUB_TOKEN }}" \\\\
            -H "Accept: application/vnd.github.v3+json" \\\\
            https://api.github.com/repos/\\$\{{ github.repository }}/actions/workflows/deploy.yml/dispatches \\\\
            -d '{"ref":"${sanitizedBranchName}"}'
          echo "Restart triggered successfully"`;

          */

   /* const workflowContent = `name: SUBZERO-MD-DEPLOY

on:
  workflow_dispatch:

jobs:
  loop-task:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: 20

      - name: Install Dependencies
        run: npm install

      - name: Run Bot (loop & auto-restart if crash)
        run: |
          echo "Running SUBZERO-MD in auto-restart mode..."
          timeout 18000 bash -c 'while true; do npm start || echo "Bot crashed, restarting..."; sleep 2; done'

      - name: Re-Trigger Workflow
        if: always()
        run: |
          echo "Re-running workflow..."
          curl -X POST \
            -H "Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}" \
            -H "Accept: application/vnd.github.v3+json" \
            https://api.github.com/repos/${{ github.repository }}/actions/workflows/deploy.yml/dispatches \
          -d '{"ref":"${sanitizedBranchName}"}'`;
*/
        const workflowContent = `name: SUBZERO-MD-DEPLOY
on:
  workflow_dispatch:
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '20'

      - name: Install Dependencies
        run: |
          echo "=== INSTALLING DEPENDENCIES ==="
          npm install --production

      - name: Verify Configuration
        run: |
          echo "=== CONFIGURATION CHECK ==="
          if [ -f "settings.js" ]; then
            echo "✓ Configuration file found"
            echo "Session ID present: $(grep -q 'SESSION_ID' settings.js && echo 'Yes' || echo 'No')"
          else
            echo "✗ Configuration file missing!"
            exit 1
          fi

      - name: Run Bot
        timeout-minutes: 300
        run: |
          echo "=== STARTING BOT AT $(date) ==="

          # Run bot with automatic restart on crash
          attempt=1
          max_attempts=999

          while [ $attempt -le $max_attempts ]; do
            echo ">>> Bot Start Attempt #$attempt at $(date '+%Y-%m-%d %H:%M:%S')"

            npm start 2>&1 | tee -a bot.log | while IFS= read -r line; do
              echo "[$(date '+%H:%M:%S')] $line"

              # Detect successful startup
              if echo "$line" | grep -qiE "(connected|online|ready|started|listening)"; then
                echo "✓ Bot activity detected!"
              fi
            done

            exit_code=\${PIPESTATUS[0]}
            echo ">>> Bot stopped (exit code: $exit_code) at $(date '+%Y-%m-%d %H:%M:%S')"

            if [ $exit_code -eq 0 ]; then
              echo "Normal exit detected, restarting in 3 seconds..."
              sleep 3
            else
              echo "Crash detected, restarting in 8 seconds..."
              sleep 8
            fi

            attempt=$((attempt + 1))
          done

      - name: Workflow Completion
        if: always()
        run: |
          echo "=== WORKFLOW ENDED AT $(date) ==="
          if [ -f "bot.log" ]; then
            echo "Last 50 log lines:"
            tail -50 bot.log
          fi

      - name: Auto Re-trigger
        if: always()
        run: |
          echo "Scheduling workflow restart in 60 seconds..."
          sleep 60

          curl -X POST \\
            -H "Authorization: Bearer \${{ secrets.GITHUB_TOKEN }}" \\
            -H "Accept: application/vnd.github.v3+json" \\
            https://api.github.com/repos/\${{ github.repository }}/actions/workflows/deploy.yml/dispatches \\
            -d '{"ref":"\${{ github.ref_name }}"}'

          echo "✓ Workflow restart triggered successfully"`;


        try {
          // First check if file exists on the deployment branch
          let existingFile;
          try {
            existingFile = await makeUserGitHubRequest('GET', `contents/.github/workflows/${WORKFLOW_FILE}?ref=${sanitizedBranchName}`);
            console.log('Found existing workflow file on deployment branch');
          } catch (branchError) {
            // File doesn't exist on deployment branch, that's okay for new branches
            console.log('No workflow file on deployment branch yet, will create it');
          }

          if (existingFile) {
            // Update existing file on deployment branch
            await makeUserGitHubRequest('PUT', `contents/.github/workflows/${WORKFLOW_FILE}`, {
              message: `Update workflow for ${sanitizedBranchName}`,
              content: Buffer.from(workflowContent).toString('base64'),
              sha: existingFile.sha,
              branch: sanitizedBranchName
            });
            console.log('✓ Workflow file updated');
          } else {
            // Create new file on deployment branch
            await makeUserGitHubRequest('PUT', `contents/.github/workflows/${WORKFLOW_FILE}`, {
              message: `Create workflow for ${sanitizedBranchName}`,
              content: Buffer.from(workflowContent).toString('base64'),
              branch: sanitizedBranchName
            });
            console.log('✓ Workflow file created');
          }
        } catch (error) {
          console.error('Error managing workflow file:', error);
          throw new Error(`Failed to create/update workflow file: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }

        // Wait for GitHub to process workflow file and make it available for dispatches
        console.log('Waiting for GitHub to process workflow file...');
        await new Promise(resolve => setTimeout(resolve, 5000));

        // Trigger workflow
        console.log(`Triggering workflow for branch: ${sanitizedBranchName}`);
        await makeUserGitHubRequest('POST', `actions/workflows/${WORKFLOW_FILE}/dispatches`, {
          ref: sanitizedBranchName
        });
        console.log('✓ Workflow triggered successfully');

        // Create deployment record
        const now = new Date();
        const nextChargeDate = new Date(now.getTime() + 24 * 60 * 60 * 1000);

        const deploymentData = insertDeploymentSchema.parse({
          userId,
          name: sanitizedBranchName,
          branchName: sanitizedBranchName,
          deploymentNumber,
          status: "deploying", // Set status to deploying initially
          configuration: `User GitHub: ${REPO_OWNER}/${REPO_NAME}`, // Indicate it's using user's GitHub
          cost: deploymentFee,
          lastChargeDate: now,
          nextChargeDate: nextChargeDate,
          // These fields are not directly used in this deployment type but kept for schema consistency
          githubToken: GITHUB_TOKEN, 
          githubOwner: REPO_OWNER,
          githubRepo: REPO_NAME
        });

        const deployment = await storage.createDeployment(deploymentData);
        console.log('Deployment record created:', deployment._id);

        // Update repository's branches array (optional, depends on schema)
        // This might require fetching the repo details first if not already done
        // await storage.updateRepositoryBranches(repositoryId, [...currentBranches, sanitizedBranchName]);

        res.json({ 
          success: true, 
          message: 'Deployment started successfully using your GitHub account!', 
          branch: sanitizedBranchName,
          deployment,
          repo: `${REPO_OWNER}/${REPO_NAME}`
        });

      } catch (githubError) {
        // Refund coins if deployment fails
        await storage.updateUserBalance(userId, deploymentFee);
        console.error('GitHub deployment failed, refunding coins.');
        throw githubError;
      }

    } catch (error) {
      console.error("Error creating user GitHub deployment:", error);
      res.status(500).json({ 
        success: false, 
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      });
    }
  });


  app.patch('/api/deployments/:id/status', isAuthenticated, async (req: any, res) => {
    try {
      const deploymentId = req.params.id;
      const { status } = req.body;
      const userId = req.user._id.toString();

      const deployment = await storage.getDeployment(deploymentId);
      if (!deployment || deployment.userId.toString() !== userId) {
        return res.status(404).json({ message: "Deployment not found" });
      }

      await storage.updateDeploymentStatus(deploymentId, status);
      res.json({ message: "Deployment status updated" });
    } catch (error) {
      console.error("Error updating deployment status:", error);
      res.status(500).json({ message: "Failed to update deployment status" });
    }
  });

  // Wallet
  app.get('/api/wallet/transactions', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const transactions = await storage.getUserTransactions(userId);
      res.json(transactions);
    } catch (error) {
      console.error("Error fetching transactions:", error);
      res.status(500).json({ message: "Failed to fetch transactions" });
    }
  });

  app.post('/api/wallet/claim-daily', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();

      // Award daily reward (simplified - in production, check if already claimed today)
      await storage.updateUserBalance(userId, 10);
      await storage.createTransaction({
        userId,
        type: "daily_reward",
        amount: 10,
        description: "Daily login bonus",
      });

      res.json({ message: "Daily reward claimed", amount: 10 });
    } catch (error) {
      console.error("Error claiming daily reward:", error);
      res.status(500).json({ message: "Failed to claim daily reward" });
    }
  });

  // Referrals
  app.get('/api/referrals', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const referrals = await storage.getUserReferrals(userId);
      res.json(referrals);
    } catch (error) {
      console.error("Error fetching referrals:", error);
      res.status(500).json({ message: "Failed to fetch referrals" });
    }
  });

  app.get('/api/referrals/stats', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const user = await storage.getUser(userId);
      const stats = await storage.getReferralStats(userId);

      res.json({
        ...stats,
        referralCode: user?.referralCode,
      });
    } catch (error) {
      console.error("Error fetching referral stats:", error);
      res.status(500).json({ message: "Failed to fetch referral stats" });
    }
  });

  // Public route for referral validation
  app.get('/api/referral/:code', async (req, res) => {
    try {
      const { code } = req.params;
      const user = await storage.getUserByReferralCode(code);

      if (user) {
        res.json({ valid: true, referrerId: user._id.toString() });
      } else {
        res.json({ valid: false });
      }
    } catch (error) {
      console.error("Error validating referral code:", error);
      res.status(500).json({ message: "Failed to validate referral code" });
    }
  });

  // Coin claiming routes
  app.get('/api/coins/claim-status', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      const now = new Date();
      const lastClaim = user.lastClaimDate;
      const canClaim = !lastClaim || (now.getTime() - lastClaim.getTime()) >= 24 * 60 * 60 * 1000; // 24 hours

      let timeUntilNextClaim = 0;
      if (!canClaim && lastClaim) {
        const nextClaimTime = new Date(lastClaim.getTime() + 24 * 60 * 60 * 1000);
        timeUntilNextClaim = Math.max(0, nextClaimTime.getTime() - now.getTime());
      }

      // Get admin-configured claim amount
      const claimAmountSetting = await storage.getAppSetting('daily_claim_amount');
      const claimAmount = parseInt(claimAmountSetting?.value) || 50; // Default 50 coins

      res.json({
        canClaim,
        timeUntilNextClaim,
        claimAmount,
        lastClaimDate: lastClaim
      });
    } catch (error) {
      console.error('Error getting claim status:', error);
      res.status(500).json({ message: 'Failed to get claim status' });
    }
  });

  app.post('/api/coins/claim', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      const now = new Date();
      const lastClaim = user.lastClaimDate;

      // Check if 24 hours have passed
      if (lastClaim && (now.getTime() - lastClaim.getTime()) < 24 * 60 * 60 * 1000) {
        const nextClaimTime = new Date(lastClaim.getTime() + 24 * 60 * 60 * 1000);
        return res.status(400).json({ 
          message: 'Daily claim not available yet',
          nextClaimTime
        });
      }

      // Get admin-configured claim amount
      const claimAmountSetting = await storage.getAppSetting('daily_claim_amount');
      const claimAmount = parseInt(claimAmountSetting?.value) || 50;

      // Update user's last claim date and coin balance
      await storage.updateUserClaimDate(userId, now);
      await storage.updateUserBalance(userId, claimAmount);

      // Create transaction record
      await storage.createTransaction({
        userId,
        type: 'daily_claim',
        amount: claimAmount,
        description: 'Daily coin claim reward'
      });

      // Get updated user balance
      const updatedUser = await storage.getUser(userId);
      const newBalance = updatedUser?.coinBalance || (user.coinBalance + claimAmount);

      res.json({
        message: 'Coins claimed successfully',
        amount: claimAmount,
        newBalance: newBalance
      });
    } catch (error) {
      console.error('Error claiming coins:', error);
      res.status(500).json({ message: 'Failed to claim coins' });
    }
  });

  // Admin authentication routes
  app.post('/api/admin/login', adminLogin);

  // Admin dashboard stats
  app.get('/api/admin/stats', requireAdmin, async (req, res) => {
    try {
      const stats = await storage.getAdminStats();
      res.json(stats);
    } catch (error) {
      console.error('Error fetching admin stats:', error);
      res.status(500).json({ message: 'Failed to fetch admin stats' });
    }
  });

  // User management routes
  app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 50;
      const offset = parseInt(req.query.offset as string) || 0;
      const search = req.query.search as string;

      let users;
      if (search) {
        users = await storage.searchUsers(search, limit);
      } else {
        users = await storage.getAllUsers(limit, offset);
      }

      res.json(users);
    } catch (error) {
      console.error('Error fetching users:', error);
      res.status(500).json({ message: 'Failed to fetch users' });
    }
  });

  // Update user status (ban/unban/restrict)
  app.patch('/api/admin/users/:userId/status', requireAdmin, async (req, res) => {
    const { userId } = req.params;
    const { status, restrictions } = req.body;

    if (!status || !['active', 'banned', 'restricted'].includes(status)) {
      return res.status(400).json({ message: 'Valid status required: active, banned, or restricted' });
    }

    try {
      await storage.updateUserStatus(userId, status, restrictions);

      // Create notification
      await storage.createAdminNotification({
        type: 'user_status_change',
        title: 'User Status Changed',
        message: `User status changed to ${status}`,
        data: { userId, status, restrictions },
        read: false
      });

      res.json({ message: 'User status updated successfully' });
    } catch (error) {
      console.error('Error updating user status:', error);
      res.status(500).json({ message: 'Failed to update user status' });
    }
  });

  // Update user coins
  app.patch('/api/admin/users/:userId/coins', requireAdmin, async (req, res) => {
    const { userId } = req.params;
    const { amount, reason } = req.body;
    const adminId = (req.user as any)?._id?.toString();

    if (typeof amount !== 'number') {
      return res.status(400).json({ message: 'Amount must be a number' });
    }

    if (!reason) {
      return res.status(400).json({ message: 'Reason is required' });
    }

    try {
      await storage.updateUserCoins(userId, amount, reason, adminId);
      res.json({ message: 'User coins updated successfully' });
    } catch (error) {
      console.error('Error updating user coins:', error);
      res.status(500).json({ message: 'Failed to update user coins' });
    }
  });

  // Promote user to admin (super admin only)
  app.patch('/api/admin/users/:userId/promote', requireSuperAdmin, async (req, res) => {
    const { userId } = req.params;
    const adminId = (req.user as any)?._id?.toString();

    try {
      await storage.promoteToAdmin(userId, adminId);
      res.json({ message: 'User promoted to admin successfully' });
    } catch (error) {
      console.error('Error promoting user:', error);
      res.status(500).json({ message: 'Failed to promote user' });
    }
  });

  // Demote admin to user (super admin only)
  app.patch('/api/admin/users/:userId/demote', requireSuperAdmin, async (req, res) => {
    const { userId } = req.params;
    const adminId = (req.user as any)?._id?.toString();

    try {
      // Prevent super admin from demoting themselves
      if (userId === adminId) {
        return res.status(400).json({ message: 'Cannot demote yourself' });
      }

      await storage.demoteFromAdmin(userId, adminId);
      res.json({ message: 'Admin demoted to user successfully' });
    } catch (error) {
      console.error('Error demoting admin:', error);
      res.status(500).json({ message: 'Failed to demote admin' });
    }
  });

  // Delete admin (super admin only)
  app.delete('/api/admin/users/:userId/admin', requireSuperAdmin, async (req, res) => {
    const { userId } = req.params;
    const adminId = (req.user as any)?._id?.toString();

    try {
      // Prevent super admin from deleting themselves
      if (userId === adminId) {
        return res.status(400).json({ message: 'Cannot delete yourself' });
      }

      // Check if target user is actually an admin
      const targetUser = await storage.getUser(userId);
      if (!targetUser || !targetUser.isAdmin) {
        return res.status(400).json({ message: 'User is not an admin' });
      }

      await storage.deleteAdmin(userId, adminId);
      res.json({ message: 'Admin deleted successfully' });
    } catch (error) {
      console.error('Error deleting admin:', error);
      res.status(500).json({ message: 'Failed to delete admin' });
    }
  });

  // Get users by device fingerprint
  app.get('/api/admin/users/by-device/:fingerprint', requireAdmin, async (req, res) => {
    const { fingerprint } = req.params;

    try {
      const users = await storage.getUsersByDeviceFingerprint(fingerprint);
      res.json(users);
    } catch (error) {
      console.error('Error fetching users by device fingerprint:', error);
      res.status(500).json({ message: 'Failed to fetch users by device fingerprint' });
    }
  });

  // Delete user (super admin only)
  app.delete('/api/admin/users/:userId', requireSuperAdmin, async (req, res) => {
    const { userId } = req.params;
    const adminId = (req.user as any)?._id?.toString();

    try {
      await storage.deleteUser(userId, adminId);
      res.json({ message: 'User deleted successfully' });
    } catch (error) {
      console.error('Error deleting user:', error);
      res.status(500).json({ message: 'Failed to delete user' });
    }
  });

  // Device fingerprint banning endpoints
  app.post('/api/admin/device/ban', requireAdmin, async (req, res) => {
    const { deviceFingerprint, reason } = req.body;
    const adminId = (req.user as any)?._id?.toString();

    if (!deviceFingerprint) {
      return res.status(400).json({ message: 'Device fingerprint is required' });
    }

    if (!reason) {
      return res.status(400).json({ message: 'Reason is required' });
    }

    try {
      await storage.banDeviceFingerprint(deviceFingerprint, reason, adminId);
      res.json({ message: 'Device fingerprint banned successfully' });
    } catch (error) {
      console.error('Error banning device fingerprint:', error);
      res.status(500).json({ message: 'Failed to ban device fingerprint' });
    }
  });

  app.post('/api/admin/device/unban', requireAdmin, async (req, res) => {
    const { deviceFingerprint } = req.body;

    if (!deviceFingerprint) {
      return res.status(400).json({ message: 'Device fingerprint is required' });
    }

    try {
      await storage.unbanDeviceFingerprint(deviceFingerprint);
      res.json({ message: 'Device fingerprint unbanned successfully' });
    } catch (error) {
      console.error('Error unbanning device fingerprint:', error);
      res.status(500).json({ message: 'Failed to unban device fingerprint' });
    }
  });

  app.get('/api/admin/device/banned', requireAdmin, async (req, res) => {
    try {
      const bannedDevices = await storage.getBannedDeviceFingerprints();
      res.json(bannedDevices);
    } catch (error) {
      console.error('Error fetching banned device fingerprints:', error);
      res.status(500).json({ message: 'Failed to fetch banned device fingerprints' });
    }
  });

  // Set device fingerprint in session before OAuth
  app.post('/api/auth/set-device-fingerprint', async (req, res) => {
    try {
      const { deviceFingerprint } = req.body;

      if (!deviceFingerprint) {
        return res.status(400).json({ message: 'Device fingerprint is required' });
      }

      // Store device fingerprint in session for OAuth callback
      (req as any).session.deviceFingerprint = deviceFingerprint;
      res.json({ success: true });
    } catch (error) {
      console.error('Error setting device fingerprint:', error);
      res.status(500).json({ message: 'Failed to set device fingerprint' });
    }
  });

  // Admin notifications
  app.get('/api/admin/notifications', requireAdmin, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 20;
      const notifications = await storage.getAdminNotifications(limit);
      res.json(notifications);
    } catch (error) {
      console.error('Error fetching admin notifications:', error);
      res.status(500).json({ message: 'Failed to fetch notifications' });
    }
  });

  // Admin deployments - get all deployments
  app.get('/api/admin/deployments', requireAdmin, async (req, res) => {
    try {
      const deployments = await storage.getAllDeployments();
      res.json(deployments);
    } catch (error) {
      console.error('Error fetching all deployments:', error);
      res.status(500).json({ message: 'Failed to fetch deployments' });
    }
  });

  // Mark notification as read
  app.patch('/api/admin/notifications/:id/read', requireAdmin, async (req, res) => {
    const { id } = req.params;

    try {
      await storage.markNotificationRead(id);
      res.json({ message: 'Notification marked as read' });
    } catch (error) {
      console.error('Error marking notification as read:', error);
      res.status(500).json({ message: 'Failed to mark notification as read' });
    }
  });

  // Admin delete deployment
  app.delete('/api/admin/deployments/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;

    try {
      const deployment = await storage.getDeployment(id);
      if (!deployment) {
        return res.status(404).json({ message: 'Deployment not found' });
      }

      await storage.deleteDeployment(id);

      // Log admin action
      await storage.createAdminNotification({
        type: 'admin_action',
        title: 'Deployment Deleted',
        message: `Admin deleted deployment: ${deployment.name}`,
        read: false,
        data: { deploymentId: id, deploymentName: deployment.name }
      });

      res.json({ message: 'Deployment deleted successfully' });
    } catch (error) {
      console.error('Error deleting deployment:', error);
      res.status(500).json({ message: 'Failed to delete deployment' });
    }
  });

  // App settings management
  app.get('/api/admin/settings', requireAdmin, async (req, res) => {
    try {
      const settings = await storage.getAllAppSettings();
      res.json(settings);
    } catch (error) {
      console.error('Error fetching app settings:', error);
      res.status(500).json({ message: 'Failed to fetch app settings' });
    }
  });

  // Get specific setting
  app.get('/api/admin/settings/:key', requireAdmin, async (req, res) => {
    const { key } = req.params;

    try {
      const setting = await storage.getAppSetting(key);
      if (!setting) {
        return res.status(404).json({ message: 'Setting not found' });
      }
      res.json(setting);
    } catch (error) {
      console.error('Error fetching app setting:', error);
      res.status(500).json({ message: 'Failed to fetch app setting' });
    }
  });

  // Update app setting
  app.put('/api/admin/settings/:key', requireAdmin, async (req, res) => {
    const { key } = req.params;
    const { value, description } = req.body;
    const adminId = (req.user as any)?._id?.toString();

    try {
      const settingData = insertAppSettingsSchema.parse({
        key,
        value,
        description,
        updatedBy: adminId
      });

      const setting = await storage.setAppSetting(settingData);
      res.json(setting);
    } catch (error) {
      console.error('Error updating app setting:', error);
      res.status(500).json({ message: 'Failed to update app setting' });
    }
  });

  // Initialize default IP restriction setting if it doesn't exist
  app.post('/api/admin/settings/init-ip-restriction', requireAdmin, async (req, res) => {
    try {
      // Initialize IP restriction setting and default coin balance if they don't exist
      const existingSetting = await storage.getAppSetting('max_accounts_per_ip');
      const defaultCoinSetting = await storage.getAppSetting('default_coin_balance');
      const adminId = (req.user as any)?._id?.toString();

      // Initialize IP restriction setting
      if (!existingSetting) {
        const settingData = insertAppSettingsSchema.parse({
          key: 'max_accounts_per_ip',
          value: 1,
          description: 'Maximum number of accounts allowed per IP address',
          updatedBy: adminId
        });

        await storage.setAppSetting(settingData);
      }

      // Initialize default coin balance setting
      if (!defaultCoinSetting) {
        const coinSettingData = insertAppSettingsSchema.parse({
          key: 'default_coin_balance',
          value: 20,
          description: 'Default coin balance for new users',
          updatedBy: adminId
        });

        await storage.setAppSetting(coinSettingData);
      }

      res.json({ 
        message: 'Admin settings initialized', 
        settings: {
          ipRestriction: existingSetting || { key: 'max_accounts_per_ip', value: 1 },
          defaultCoins: defaultCoinSetting || { key: 'default_coin_balance', value: 20 }
        }
      });
    } catch (error) {
      console.error('Error initializing IP restriction setting:', error);
      res.status(500).json({ message: 'Failed to initialize IP restriction setting' });
    }
  });

  // GitHub deployment settings
  // GitHub Account Management Routes

  // Get all GitHub accounts
  app.get('/api/admin/github/accounts', requireAdmin, async (req, res) => {
    try {
      const accounts = await storage.getAllGitHubAccounts();
      res.json(accounts.map(account => ({
        ...account,
        _id: account._id.toString(),
        createdAt: account.createdAt.toISOString(),
        updatedAt: account.updatedAt.toISOString(),
        lastUsed: account.lastUsed?.toISOString()
      })));
    } catch (error) {
      console.error('Error fetching GitHub accounts:', error);
      res.status(500).json({ message: 'Failed to fetch GitHub accounts' });
    }
  });

  // Create GitHub account
  app.post('/api/admin/github/accounts', requireAdmin, async (req, res) => {
    try {
      const { name, token, owner, repo, workflowFile } = req.body;

      if (!name || !token || !owner || !repo || !workflowFile) {
        return res.status(400).json({ message: 'All fields are required' });
      }

      const account = await storage.createGitHubAccount({
        name,
        token,
        owner,
        repo,
        workflowFile
      });

      res.status(201).json({
        ...account,
        _id: account._id.toString(),
        createdAt: account.createdAt.toISOString(),
        updatedAt: account.updatedAt.toISOString()
      });
    } catch (error) {
      console.error('Error creating GitHub account:', error);
      res.status(500).json({ message: 'Failed to create GitHub account' });
    }
  });

  // Update GitHub account
  app.patch('/api/admin/github/accounts/:id', requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const updates = req.body;

      await storage.updateGitHubAccount(id, updates);
      res.json({ message: 'GitHub account updated successfully' });
    } catch (error) {
      console.error('Error updating GitHub account:', error);
      res.status(500).json({ message: 'Failed to update GitHub account' });
    }
  });

  // Delete GitHub account
  app.delete('/api/admin/github/accounts/:id', requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      await storage.deleteGitHubAccount(id);
      res.json({ message: 'GitHub account deleted successfully' });
    } catch (error) {
      console.error('Error deleting GitHub account:', error);
      res.status(500).json({ message: 'Failed to delete GitHub account' });
    }
  });

  app.get('/api/admin/github/settings', requireAdmin, async (req, res) => {
    try {
      const [githubToken, repoOwner, repoName, mainBranch, workflowFile] = await Promise.all([
        storage.getAppSetting('github_token'),
        storage.getAppSetting('github_repo_owner'),
        storage.getAppSetting('github_repo_name'),
        storage.getAppSetting('github_main_branch'),
        storage.getAppSetting('github_workflow_file')
      ]);

      res.json({
        githubToken: githubToken?.value || '',
        repoOwner: repoOwner?.value || '',
        repoName: repoName?.value || '',
        mainBranch: mainBranch?.value || 'main',
        workflowFile: workflowFile?.value || 'deploy.yml'
      });
    } catch (error) {
      console.error('Error fetching GitHub settings:', error);
      res.status(500).json({ message: 'Failed to fetch GitHub settings' });
    }
  });

  app.put('/api/admin/github/settings', requireAdmin, async (req, res) => {
    try {
      const { githubToken, repoOwner, repoName, mainBranch, workflowFile } = req.body;
      const adminId = (req.user as any)?._id?.toString();

      // Update all GitHub settings
      const settings = [
        { key: 'github_token', value: githubToken, description: 'GitHub Personal Access Token for deployments' },
        { key: 'github_repo_owner', value: repoOwner, description: 'GitHub repository owner/organization' },
        { key: 'github_repo_name', value: repoName, description: 'GitHub repository name' },
        { key: 'github_main_branch', value: mainBranch || 'main', description: 'Main branch name' },
        { key: 'github_workflow_file', value: workflowFile || 'deploy.yml', description: 'GitHub Actions workflow file name' }
      ];

      for (const setting of settings) {
        try {
          const settingData = insertAppSettingsSchema.parse({
            ...setting,
            updatedBy: adminId
          });
          await storage.setAppSetting(settingData);
          console.log(`Successfully saved setting: ${setting.key}`);
        } catch (parseError) {
          console.error(`Error parsing setting ${setting.key}:`, parseError);
          throw parseError;
        }
      }

      console.log('All GitHub settings updated successfully');
      res.json({ message: 'GitHub settings updated successfully' });
    } catch (error) {
      console.error('Error updating GitHub settings:', error);
      res.status(500).json({ message: 'Failed to update GitHub settings' });
    }
  });

  // GitHub account management endpoints
  app.get('/api/admin/github/accounts', requireAdmin, async (req, res) => {
    try {
      const accounts = await storage.getAllGitHubAccounts();
      res.json(accounts);
    } catch (error) {
      console.error('Error fetching GitHub accounts:', error);
      res.status(500).json({ error: 'Failed to fetch GitHub accounts' });
    }
  });

  app.post('/api/admin/github/accounts/test/:id', requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const result = await storage.testGitHubAccountToken(id);
      res.json(result);
    } catch (error) {
      console.error('Error testing GitHub token:', error);
      res.status(500).json({ error: 'Failed to test GitHub token' });
    }
  });

  app.post('/api/admin/github/accounts', requireAdmin, async (req, res) => {
    try {
      const { name, token, owner, repo, workflowFile } = req.body;

      if (!name || !token || !owner || !repo) {
        return res.status(400).json({ error: 'All fields (name, token, owner, repo) are required' });
      }

      const account = await storage.createGitHubAccount({
        name,
        token,
        owner,
        repo,
        workflowFile: workflowFile || 'deploy.yml'
      });

      res.json(account);
    } catch (error) {
      console.error('Error creating GitHub account:', error);
      res.status(500).json({ error: 'Failed to create GitHub account' });
    }
  });

  app.put('/api/admin/github/accounts/:id/active', requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const { active } = req.body;

      await storage.setGitHubAccountActive(id, active);
      res.json({ success: true });
    } catch (error) {
      console.error('Error updating GitHub account status:', error);
      res.status(500).json({ error: 'Failed to update GitHub account status' });
    }
  });

  app.delete('/api/admin/github/accounts/:id', requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      await storage.deleteGitHubAccount(id);
      res.json({ success: true });
    } catch (error) {
      console.error('Error deleting GitHub account:', error);
      res.status(500).json({ error: 'Failed to delete GitHub account' });
    }
  });

  // User deployment logs endpoints - only access own deployments
  app.get('/api/deployments/:deploymentId/logs', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const { deploymentId } = req.params;

      // Get deployment and verify ownership
      const deployment = await storage.getDeployment(deploymentId);
      if (!deployment) {
        return res.status(404).json({ message: 'Deployment not found' });
      }

      if (deployment.userId.toString() !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }

      if (!deployment.branchName) {
        return res.status(400).json({ message: 'No branch name associated with this deployment' });
      }

      const [githubToken, repoOwner, repoName, workflowFile] = await Promise.all([
        storage.getAppSetting('github_token'),
        storage.getAppSetting('github_repo_owner'),
        storage.getAppSetting('github_repo_name'),
        storage.getAppSetting('github_workflow_file')
      ]);

      if (!githubToken?.value || !repoOwner?.value || !repoName?.value) {
        // Return deployment info with helpful message instead of error
        return res.json([{
          jobId: 1,
          jobName: 'Configuration Required',
          logs: 'GitHub integration not configured by administrator.\n\nTo enable deployment monitoring:\n1. Contact your administrator\n2. Ask them to configure GitHub settings in admin panel\n3. Provide GitHub token, repository owner, and repository name\n\nDeployment may still be running, but logs cannot be accessed without GitHub configuration.',
          status: 'configuration_missing',
          conclusion: 'neutral',
          createdAt: deployment.createdAt || new Date().toISOString(),
          updatedAt: deployment.updatedAt || new Date().toISOString()
        }]);
      }

      const GITHUB_TOKEN = githubToken.value;
      const REPO_OWNER = repoOwner.value;
      const REPO_NAME = repoName.value;
      const WORKFLOW_FILE = workflowFile?.value || 'deploy.yml';

      // Get workflow runs for the specific branch
      const runsUrl = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/actions/workflows/${WORKFLOW_FILE}/runs?branch=${deployment.branchName}&per_page=10`;
      const runsResponse = await fetch(runsUrl, {
        headers: {
          'Authorization': `token ${GITHUB_TOKEN}`,
          'Accept': 'application/vnd.github.v3+json'
        }
      });

      if (!runsResponse.ok) {
        throw new Error(`GitHub API error: ${runsResponse.statusText}`);
      }

      const runsData = await runsResponse.json();

      // If no runs found, try to get the latest runs regardless of branch
      let workflowRuns = runsData.workflow_runs || [];
      if (workflowRuns.length === 0) {
        // Try to get any runs for this workflow
        const allRunsUrl = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/actions/workflows/${WORKFLOW_FILE}/runs?per_page=5`;
        const allRunsResponse = await fetch(allRunsUrl, {
          headers: {
            'Authorization': `token ${GITHUB_TOKEN}`,
            'Accept': 'application/vnd.github.v3+json'
          }
        });

        if (allRunsResponse.ok) {
          const allRunsData = await allRunsResponse.json();
          // Filter runs that might be related to this deployment
          workflowRuns = (allRunsData.workflow_runs || []).filter((run: any) => 
            run.head_branch === deployment.branchName || 
            run.display_title?.includes(deployment.branchName) ||
            run.display_title?.includes(deployment.name)
          );
        }
      }

      // Get detailed logs for the most recent run
      let detailedLogs = [];
      if (workflowRuns.length > 0) {
        const latestRun = workflowRuns[0];
        try {
          // Get jobs for the latest run
          const jobsUrl = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/actions/runs/${latestRun.id}/jobs`;
          const jobsResponse = await fetch(jobsUrl, {
            headers: {
              'Authorization': `token ${GITHUB_TOKEN}`,
              'Accept': 'application/vnd.github.v3+json'
            }
          });

          if (jobsResponse.ok) {
            const jobsData = await jobsResponse.json();
            const jobs = jobsData.jobs || [];

            // Get logs for each job
            for (const job of jobs) {
              const logsUrl = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/actions/jobs/${job.id}/logs`;
              const logsResponse = await fetch(logsUrl, {
                headers: {
                  'Authorization': `token ${GITHUB_TOKEN}`,
                  'Accept': 'application/vnd.github.v3+json'
                }
              });

              if (logsResponse.ok) {
                const logs = await logsResponse.text();

                // Check if app has started in logs for automatic status detection
                const hasAppStarted = logs.includes('npm start') || 
                                    logs.includes('node index.js') || 
                                    logs.includes('Server is running') ||
                                    logs.includes('Application started') ||
                                    logs.includes('listening on port');

                // Update deployment status if app has started
                if (hasAppStarted && deployment.status === 'deploying') {
                  try {
                    await storage.updateDeploymentStatus(deployment._id.toString(), 'active');
                    console.log(`Deployment ${deployment._id.toString()} status updated to active - app started detected`);
                  } catch (updateError) {
                    console.error('Error updating deployment status:', updateError);
                  }
                }

                detailedLogs.push({
                  jobId: job.id,
                  jobName: job.name,
                  status: job.status,
                  conclusion: job.conclusion,
                  logs: logs || 'No logs available',
                  createdAt: job.created_at,
                  updatedAt: job.completed_at || new Date().toISOString()
                });
              }
            }
          }
        } catch (error) {
          console.error('Error fetching detailed logs:', error);
        }
      }

      // Check if we found any logs to show deployment status
      if (detailedLogs.length === 0) {
        detailedLogs.push({
          jobId: 1,
          jobName: 'Deployment Status',
          logs: workflowRuns.length > 0 ? 
            'Deployment workflow found but logs are not yet available.\nThe deployment may still be initializing. Please check back in a few moments.' :
            'No deployment workflows found for this branch.\nThe deployment may not have started yet or GitHub Actions may not be properly configured.',
          status: workflowRuns.length > 0 ? 'pending' : 'not_started',
          conclusion: 'neutral'
        });
      }

      res.json(detailedLogs);
    } catch (error) {
      console.error('Error fetching deployment logs:', error);
      res.status(500).json({ message: 'Failed to fetch deployment logs' });
    }
  });

  // User endpoint to get specific workflow run logs  
  app.get('/api/deployments/:deploymentId/runs/:runId/logs', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const { deploymentId, runId } = req.params;

      // Get deployment and verify ownership
      const deployment = await storage.getDeployment(deploymentId);
      if (!deployment) {
        return res.status(404).json({ message: 'Deployment not found' });
      }

      if (deployment.userId.toString() !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }

      const [githubToken, repoOwner, repoName] = await Promise.all([
        storage.getAppSetting('github_token'),
        storage.getAppSetting('github_repo_owner'),
        storage.getAppSetting('github_repo_name')
      ]);

      if (!githubToken?.value || !repoOwner?.value || !repoName?.value) {
        // Return deployment info with helpful message for specific run logs
        return res.json([{
          jobId: parseInt(runId) || 1,
          jobName: 'Configuration Required',
          logs: 'GitHub integration not configured by administrator. Cannot access specific workflow run logs.\n\nContact your administrator to configure GitHub settings.\n',
          status: 'configuration_missing',
          conclusion: 'neutral'
        }]);
      }

      const GITHUB_TOKEN = githubToken.value;
      const REPO_OWNER = repoOwner.value;
      const REPO_NAME = repoName.value;

      // Get jobs for the workflow run
      const jobsUrl = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/actions/runs/${runId}/jobs`;
      const jobsResponse = await fetch(jobsUrl, {
        headers: {
          'Authorization': `token ${GITHUB_TOKEN}`,
          'Accept': 'application/vnd.github.v3+json'
        }
      });

      if (!jobsResponse.ok) {
        throw new Error(`GitHub API error: ${jobsResponse.statusText}`);
      }

      const jobsData = await jobsResponse.json();

      // Get logs for each job
      const logsPromises = jobsData.jobs.map(async (job: any) => {
        try {
          const logsUrl = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/actions/jobs/${job.id}/logs`;
          const logsResponse = await fetch(logsUrl, {
            headers: {
              'Authorization': `token ${GITHUB_TOKEN}`,
              'Accept': 'application/vnd.github.v3+json'
            }
          });

          if (logsResponse.ok) {
            const logs = await logsResponse.text();
            return { jobId: job.id, jobName: job.name, logs };
          }
          return { jobId: job.id, jobName: job.name, logs: 'No logs available' };
        } catch (error) {
          return { jobId: job.id, jobName: job.name, logs: 'Error fetching logs' };
        }
      });

      const allLogs = await Promise.all(logsPromises);
      res.json({ 
        deployment,
        jobs: jobsData.jobs, 
        logs: allLogs 
      });
    } catch (error) {
      console.error('Error fetching specific workflow logs:', error);
      res.status(500).json({ message: 'Failed to fetch workflow logs' });
    }
  });

  // Admin: Get deployment logs (admin access)
  app.get('/api/admin/deployments/:deploymentId/logs', requireAdmin, async (req: any, res) => {
    try {
      const { deploymentId } = req.params;

      // Get deployment
      const deployment = await storage.getDeployment(deploymentId);
      if (!deployment) {
        return res.status(404).json({ message: 'Deployment not found' });
      }

      if (!deployment.branchName) {
        return res.status(400).json({ message: 'No branch name associated with this deployment' });
      }

      const [githubToken, repoOwner, repoName, workflowFile] = await Promise.all([
        storage.getAppSetting('github_token'),
        storage.getAppSetting('github_repo_owner'),
        storage.getAppSetting('github_repo_name'),
        storage.getAppSetting('github_workflow_file')
      ]);

      if (!githubToken?.value || !repoOwner?.value || !repoName?.value) {
        return res.json([{
          jobId: 1,
          jobName: 'Configuration Required',
          logs: 'GitHub integration not configured by administrator.',
          status: 'configuration_missing',
          conclusion: 'neutral'
        }]);
      }

      const GITHUB_TOKEN = githubToken.value;
      const REPO_OWNER = repoOwner.value;
      const REPO_NAME = repoName.value;
      const WORKFLOW_FILE = workflowFile?.value || 'deploy.yml';

      // Get workflow runs for the specific branch
      const runsUrl = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/actions/workflows/${WORKFLOW_FILE}/runs?branch=${deployment.branchName}&per_page=10`;
      const runsResponse = await fetch(runsUrl, {
        headers: {
          'Authorization': `token ${GITHUB_TOKEN}`,
          'Accept': 'application/vnd.github.v3+json'
        }
      });

      if (!runsResponse.ok) {
        throw new Error(`GitHub API error: ${runsResponse.statusText}`);
      }

      const runsData = await runsResponse.json();

      let detailedLogs = [];
      if (runsData.workflow_runs && runsData.workflow_runs.length > 0) {
        const latestRun = runsData.workflow_runs[0];
        const jobsUrl = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/actions/runs/${latestRun.id}/jobs`;
        const jobsResponse = await fetch(jobsUrl, {
          headers: {
            'Authorization': `token ${GITHUB_TOKEN}`,
            'Accept': 'application/vnd.github.v3+json'
          }
        });

        if (jobsResponse.ok) {
          const jobsData = await jobsResponse.json();
          const jobs = jobsData.jobs || [];

          for (const job of jobs) {
            const logsUrl = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/actions/jobs/${job.id}/logs`;
            const logsResponse = await fetch(logsUrl, {
              headers: {
                'Authorization': `token ${GITHUB_TOKEN}`,
                'Accept': 'application/vnd.github.v3+json'
              }
            });

            if (logsResponse.ok) {
              const logs = await logsResponse.text();
              detailedLogs.push({
                jobId: job.id,
                jobName: job.name,
                logs: logs || 'No logs available',
                createdAt: job.created_at,
                updatedAt: job.completed_at || new Date().toISOString()
              });
            }
          }
        }
      }

      if (detailedLogs.length === 0) {
        detailedLogs.push({
          jobId: 1,
          jobName: 'Deployment Status',
          logs: runsData.workflow_runs && runsData.workflow_runs.length > 0 ? 
            'Deployment workflow found but logs are not yet available.' :
            'No deployment workflows found for this branch.',
          status: 'pending',
          conclusion: 'neutral'
        });
      }

      res.json(detailedLogs);
    } catch (error) {
      console.error('Error fetching deployment logs (admin):', error);
      res.status(500).json({ message: 'Failed to fetch deployment logs' });
    }
  });


  // GitHub API test endpoints for branches and workflows
  app.get('/api/admin/github/branches', isAuthenticated, requireAdmin, async (req: any, res) => {
    try {
      const [githubToken, repoOwner, repoName] = await Promise.all([
        storage.getAppSetting('github_token'),
        storage.getAppSetting('github_repo_owner'),
        storage.getAppSetting('github_repo_name')
      ]);

      if (!githubToken?.value || !repoOwner?.value || !repoName?.value) {
        return res.status(400).json({ message: 'GitHub settings not configured' });
      }

      const response = await fetch(`https://api.github.com/repos/${repoOwner.value}/${repoName.value}/branches`, {
        headers: {
          'Authorization': `token ${githubToken.value}`,
          'Accept': 'application/vnd.github.v3+json'
        }
      });

      if (!response.ok) {
        throw new Error(`GitHub API error: ${response.statusText}`);
      }

      const branches = await response.json();
      res.json(branches);
    } catch (error) {
      console.error('Error fetching branches:', error);
      res.status(500).json({ message: 'Failed to fetch branches' });
    }
  });

  app.get('/api/admin/github/workflows', isAuthenticated, requireAdmin, async (req: any, res) => {
    try {
      const [githubToken, repoOwner, repoName, workflowFile] = await Promise.all([
        storage.getAppSetting('github_token'),
        storage.getAppSetting('github_repo_owner'),
        storage.getAppSetting('github_repo_name'),
        storage.getAppSetting('github_workflow_file')
      ]);

      if (!githubToken?.value || !repoOwner?.value || !repoName?.value) {
        return res.status(400).json({ message: 'GitHub settings not configured' });
      }

      const WORKFLOW_FILE = workflowFile?.value || 'deploy.yml';
      const response = await fetch(`https://api.github.com/repos/${repoOwner.value}/${repoName.value}/actions/workflows/${WORKFLOW_FILE}/runs?per_page=20`, {
        headers: {
          'Authorization': `token ${githubToken.value}`,
          'Accept': 'application/vnd.github.v3+json'
        }
      });

      if (!response.ok) {
        throw new Error(`GitHub API error: ${response.statusText}`);
      }

      const data = await response.json();
      res.json(data.workflow_runs || []);
    } catch (error) {
      console.error('Error fetching workflows:', error);
      res.status(500).json({ message: 'Failed to fetch workflows' });
    }
  });

  app.delete('/api/admin/github/branches', isAuthenticated, requireAdmin, async (req, res) => {
    try {
      const { branches } = req.body;
      if (!Array.isArray(branches) || branches.length === 0) {
        return res.status(400).json({ message: 'Invalid branches array' });
      }

      const [githubToken, repoOwner, repoName] = await Promise.all([
        storage.getAppSetting('github_token'),
        storage.getAppSetting('github_repo_owner'),
        storage.getAppSetting('github_repo_name')
      ]);

      if (!githubToken?.value || !repoOwner?.value || !repoName?.value) {
        return res.status(400).json({ message: 'GitHub settings not configured' });
      }

      const results = [];
      for (const branchName of branches) {
        // Don't allow deletion of main/master branches
        if (branchName === 'main' || branchName === 'master') {
          results.push({ branch: branchName, status: 'skipped', reason: 'Protected branch' });
          continue;
        }

        try {
          const response = await fetch(`https://api.github.com/repos/${repoOwner.value}/${repoName.value}/git/refs/heads/${branchName}`, {
            method: 'DELETE',
            headers: {
              'Authorization': `token ${githubToken.value}`,
              'Accept': 'application/vnd.github.v3+json'
            }
          });

          if (response.ok) {
            results.push({ branch: branchName, status: 'deleted' });
          } else {
            results.push({ branch: branchName, status: 'failed', reason: `HTTP ${response.status}` });
          }
        } catch (error) {
          results.push({ branch: branchName, status: 'failed', reason: 'Network error' });
        }
      }

      res.json({ results });
    } catch (error) {
      console.error('Error deleting branches:', error);
      res.status(500).json({ message: 'Failed to delete branches' });
    }
  });

  // Admin maintenance mode routes
  app.get('/api/admin/maintenance/status', requireAdmin, async (req, res) => {
    try {
      const isEnabled = await storage.isMaintenanceModeEnabled();
      const [message, estimatedTime, endTime] = await Promise.all([
        storage.getAppSetting('maintenance_message'),
        storage.getAppSetting('maintenance_estimated_time'),
        storage.getAppSetting('maintenance_end_time')
      ]);

      res.json({
        enabled: isEnabled,
        message: message?.value || '',
        estimatedTime: estimatedTime?.value || '',
        endTime: endTime?.value || null
      });
    } catch (error) {
      console.error('Error getting maintenance status:', error);
      res.status(500).json({ error: 'Failed to get maintenance status' });
    }
  });

  app.post('/api/admin/maintenance/toggle', requireAdmin, async (req, res) => {
    try {
      const { enabled, message, estimatedTime, endTime } = req.body;
      const adminId = (req.user as any)?._id?.toString();

      await storage.setMaintenanceMode(enabled, adminId, message);

      if (estimatedTime) {
        await storage.setAppSetting({
          key: 'maintenance_estimated_time',
          value: estimatedTime,
          description: 'Estimated maintenance completion time',
          updatedBy: adminId
        });
      }

      // Set maintenance end time for countdown
      if (enabled && endTime) {
        await storage.setAppSetting({
          key: 'maintenance_end_time',
          value: endTime,
          description: 'Maintenance mode automatic end time',
          updatedBy: adminId
        });
      } else if (!enabled) {
        // Clear end time when maintenance is disabled
        await storage.deleteAppSetting('maintenance_end_time');
      }

      res.json({ 
        message: enabled ? 'Maintenance mode enabled' : 'Maintenance mode disabled',
        enabled 
      });
    } catch (error) {
      console.error('Error toggling maintenance mode:', error);
      res.status(500).json({ error: 'Failed to toggle maintenance mode' });
    }
  });

  // Admin coin claim configuration
  app.get('/api/admin/coins/claim-config', requireAdmin, async (req, res) => {
    try {
      const claimAmountSetting = await storage.getAppSetting('daily_claim_amount');
      const claimAmount = claimAmountSetting?.value || 50;

      res.json({
        dailyClaimAmount: claimAmount
      });
    } catch (error) {
      console.error('Error getting coin claim config:', error);
      res.status(500).json({ error: 'Failed to get coin claim config' });
    }
  });

  app.post('/api/admin/coins/claim-config', requireAdmin, async (req, res) => {
    try {
      const { dailyClaimAmount } = req.body;
      const adminId = (req.user as any)?._id?.toString();

      if (!dailyClaimAmount || dailyClaimAmount < 1 || dailyClaimAmount > 1000) {
        return res.status(400).json({ error: 'Daily claim amount must be between 1 and 1000 coins' });
      }

      await storage.setAppSetting({
        key: 'daily_claim_amount',
        value: parseInt(dailyClaimAmount),
        description: 'Daily coin claim reward amount',
        updatedBy: adminId
      });

      res.json({
        message: 'Daily claim amount updated successfully',
        dailyClaimAmount: parseInt(dailyClaimAmount)
      });
    } catch (error) {
      console.error('Error updating coin claim config:', error);
      res.status(500).json({ error: 'Failed to update coin claim config' });
    }
  });

  // Get deployment fee configuration
  app.get('/api/admin/coins/deployment-fee', requireAdmin, async (req, res) => {
    try {
      const setting = await storage.getAppSetting('deployment_fee');
      const deploymentFee = setting?.value || 5;
      res.json({ deploymentFee });
    } catch (error) {
      console.error('Error fetching deployment fee:', error);
      res.status(500).json({ message: 'Failed to fetch deployment fee' });
    }
  });

  // Update deployment fee
  app.post('/api/admin/coins/deployment-fee', requireAdmin, async (req, res) => {
    try {
      const { deploymentFee } = req.body;
      const adminId = (req.user as any)?._id?.toString();

      if (typeof deploymentFee !== 'number' || deploymentFee < 0) {
        return res.status(400).json({ message: 'Valid deployment fee required' });
      }

      await storage.setAppSetting({
        key: 'deployment_fee',
        value: deploymentFee,
        description: 'Fee charged for creating new deployments',
        updatedBy: adminId
      });

      res.json({ message: 'Deployment fee updated successfully' });
    } catch (error) {
      console.error('Error updating deployment fee:', error);
      res.status(500).json({ message: 'Failed to update deployment fee' });
    }
  });

  // Get daily charge configuration
  app.get('/api/admin/coins/daily-charge', requireAdmin, async (req, res) => {
    try {
      const setting = await storage.getAppSetting('daily_charge');
      const dailyCharge = setting?.value || 0; // Default to 0 coins daily maintenance
      res.json({ dailyCharge });
    } catch (error) {
      console.error('Error fetching daily charge:', error);
      res.status(500).json({ message: 'Failed to fetch daily charge' });
    }
  });

  // Update daily charge
  app.post('/api/admin/coins/daily-charge', requireAdmin, async (req, res) => {
    try {
      const { dailyCharge } = req.body;
      const adminId = (req.user as any)?._id?.toString();

      if (typeof dailyCharge !== 'number' || dailyCharge < 0) {
        return res.status(400).json({ message: 'Valid daily charge required' });
      }

      await storage.setAppSetting({
        key: 'daily_charge',
        value: dailyCharge,
        description: 'Daily maintenance charge for active deployments',
        updatedBy: adminId
      });

      res.json({ message: 'Daily charge updated successfully' });
    } catch (error) {
      console.error('Error updating daily charge:', error);
      res.status(500).json({ message: 'Failed to update daily charge' });
    }
  });

  // Admin currency management routes
  app.get('/api/admin/currency', requireAdmin, async (req, res) => {
    try {
      const [currency, rate, symbol] = await Promise.all([
        storage.getAppSetting('currency'),
        storage.getAppSetting('currency_rate'),
        storage.getAppSetting('currency_symbol')
      ]);

      res.json({
        currency: currency?.value || 'USD',
        rate: rate?.value || 0.1,
        symbol: symbol?.value || '$'
      });
    } catch (error) {
      console.error('Error getting currency settings:', error);
      res.status(500).json({ error: 'Failed to get currency settings' });
    }
  });

  app.put('/api/admin/currency', requireAdmin, async (req, res) => {
    try {
      const { currency, rate, symbol } = req.body;
      const adminId = (req.user as any)?._id?.toString();

      if (!currency || !rate || !symbol) {
        return res.status(400).json({ error: 'Currency, rate, and symbol are required' });
      }

      // Save currency settings
      await Promise.all([
        storage.setAppSetting({
          key: 'currency',
          value: currency,
          description: 'Selected currency for display',
          updatedBy: adminId
        }),
        storage.setAppSetting({
          key: 'currency_rate',
          value: parseFloat(rate),
          description: 'Exchange rate per coin',
          updatedBy: adminId
        }),
        storage.setAppSetting({
          key: 'currency_symbol',
          value: symbol,
          description: 'Currency symbol for display',
          updatedBy: adminId
        })
      ]);

      res.json({ success: true });
    } catch (error) {
      console.error('Error updating currency settings:', error);
      res.status(500).json({ error: 'Failed to update currency settings' });
    }
  });

  // Chat image upload endpoint - using base64 storage
  app.post('/api/chat/upload-image', isAuthenticated, upload.single('image'), async (req: any, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: 'No image file provided' });
      }

      // Read file and convert to base64
      const fileBuffer = fs.readFileSync(req.file.path);
      const base64Data = `data:${req.file.mimetype};base64,${fileBuffer.toString('base64')}`;

      // Clean up temporary file
      fs.unlinkSync(req.file.path);

      res.json({
        success: true,
        imageData: base64Data,
        fileName: req.file.originalname,
        fileSize: req.file.size
      });
    } catch (error) {
      console.error('Error uploading chat image:', error);
      res.status(500).json({ message: 'Failed to upload image' });
    }
  });

  // Serve uploaded images
  app.use('/uploads', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    next();
  });
  app.use('/uploads', express.static(path.join(process.cwd(), 'uploads')));

  const httpServer = createServer(app);

  // Setup WebSocket server
  const wss = new WebSocketServer({ server: httpServer, path: '/ws' });

  wss.on('connection', (ws: WebSocket, req) => {
    const clientId = crypto.randomUUID();
    wsConnections.set(clientId, ws);

    console.log(`WebSocket client connected: ${clientId}`);

    // Send connection confirmation
    ws.send(JSON.stringify({ 
      type: 'connected', 
      data: { clientId },
      timestamp: new Date().toISOString()
    }));

    ws.on('message', async (message) => {
      try {
        const data = JSON.parse(message.toString());

        // Handle deployment monitoring requests
        if (data.type === 'monitor_deployment' && data.branch) {
          startWorkflowMonitoring(data.branch);
          ws.send(JSON.stringify({
            type: 'monitoring_started',
            data: { branch: data.branch },
            timestamp: new Date().toISOString()
          }));
        }
        // Handle chat functionality
        else if (data.type === 'join_chat') {
          // Check if device fingerprint is banned
          if (data.deviceFingerprint) {
            const isBanned = await storage.isDeviceFingerprintBanned(data.deviceFingerprint);
            if (isBanned) {
              ws.send(JSON.stringify({
                type: 'error',
                code: 'DEVICE_BANNED',
                message: 'Access denied: Your device is banned from using the chat service'
              }));
              ws.close();
              return;
            }
          }

          const chatClient: ChatClient = {
            ws,
            userId: data.userId,
            username: data.username,
            isAdmin: data.isAdmin,
            role: data.role
          };

          chatClients.set(clientId, chatClient);

          // Send chat history to the new client
          try {
            const messages = await storage.getChatMessages(50);
            ws.send(JSON.stringify({
              type: 'chat_history',
              messages: messages.map(msg => ({
                ...msg,
                _id: msg._id.toString(),
                userId: msg.userId.toString(),
                createdAt: msg.createdAt.toISOString()
              }))
            }));

            // Send current users list
            const users = Array.from(chatClients.values()).map(client => ({
              userId: client.userId,
              username: client.username,
              isAdmin: client.isAdmin,
              role: client.role,
              isRestricted: false
            }));

            ws.send(JSON.stringify({
              type: 'users_list',
              users
            }));

            // Broadcast user joined to other clients
            broadcastToChatClients('user_joined', {
              user: {
                userId: data.userId,
                username: data.username,
                isAdmin: data.isAdmin,
                role: data.role,
                isRestricted: false
              }
            }, clientId);

          } catch (error) {
            console.error('Error handling chat join:', error);
          }
        }
        else if (data.type === 'send_message') {
          const chatClient = chatClients.get(clientId);
          if (chatClient) {
            try {
              // Check if user is restricted
              const isRestricted = await storage.isChatRestricted(chatClient.userId);
              if (isRestricted) {
                ws.send(JSON.stringify({
                  type: 'error',
                  message: 'You are restricted from sending messages'
                }));
                return;
              }

              // Create and broadcast message
              const messageData: any = {
                userId: chatClient.userId,
                username: chatClient.username,
                message: data.message,
                messageType: data.messageType || 'text',
                isAdmin: chatClient.isAdmin,
                role: chatClient.role
              };

              // Add image data if this is an image message
              if (data.messageType === 'image') {
                messageData.imageUrl = data.imageUrl;
                messageData.imageData = data.imageData;
                messageData.fileName = data.fileName;
                messageData.fileSize = data.fileSize;
              }

              // Add reply data if this is a reply
              if (data.replyTo) {
                messageData.replyTo = data.replyTo;
                messageData.replyToMessage = data.replyToMessage;
                messageData.replyToUsername = data.replyToUsername;
              }

              const chatMessage = await storage.createChatMessage(messageData);

              broadcastToChatClients('chat_message', {
                message: {
                  ...chatMessage,
                  _id: chatMessage._id.toString(),
                  userId: chatMessage.userId.toString(),
                  createdAt: chatMessage.createdAt.toISOString()
                }
              });

            } catch (error) {
              console.error('Error sending chat message:', error);
              ws.send(JSON.stringify({
                type: 'error',
                message: 'Failed to send message'
              }));
            }
          }
        }
        else if (data.type === 'restrict_user') {
          const chatClient = chatClients.get(clientId);
          if (chatClient && chatClient.isAdmin) {
            try {
              await storage.restrictUserFromChat(data.userId, chatClient.userId, data.reason);

              broadcastToChatClients('user_restricted', {
                userId: data.userId,
                restrictedBy: chatClient.userId,
                reason: data.reason
              });

            } catch (error) {
              console.error('Error restricting user:', error);
              ws.send(JSON.stringify({
                type: 'error',
                message: 'Failed to restrict user'
              }));
            }
          }
        }
        else if (data.type === 'unrestrict_user') {
          const chatClient = chatClients.get(clientId);
          if (chatClient && chatClient.isAdmin) {
            try {
              await storage.unrestrictUserFromChat(data.userId);

              broadcastToChatClients('user_unrestricted', {
                userId: data.userId,
                unrestrictedBy: chatClient.userId
              });

            } catch (error) {
              console.error('Error unrestricting user:', error);
              ws.send(JSON.stringify({
                type: 'error',
                message: 'Failed to unrestrict user'
              }));
            }
          }
        }
        else if (data.type === 'update_message') {
          const chatClient = chatClients.get(clientId);
          if (chatClient) {
            try {
              const message = await storage.getChatMessage(data.messageId);
              if (message && message.userId.toString() === chatClient.userId) {
                await storage.updateChatMessage(data.messageId, data.newMessage, chatClient.userId);

                broadcastToChatClients('message_updated', {
                  messageId: data.messageId,
                  newMessage: data.newMessage,
                  editedAt: new Date().toISOString()
                });
              }
            } catch (error) {
              console.error('Error updating message:', error);
            }
          }
        }
        else if (data.type === 'delete_message') {
          const chatClient = chatClients.get(clientId);
          if (chatClient) {
            try {
              await storage.deleteChatMessage(data.messageId, chatClient.userId, chatClient.isAdmin);

              broadcastToChatClients('message_deleted', {
                messageId: data.messageId
              });

            } catch (error) {
              console.error('Error deleting message:', error);
              ws.send(JSON.stringify({
                type: 'error',
                message: 'Failed to delete message'
              }));
            }
          }
        }
        else if (data.type === 'delete_selected_messages') {
          const chatClient = chatClients.get(clientId);
          if (chatClient && Array.isArray(data.messageIds)) {
            try {
              for (const messageId of data.messageIds) {
                await storage.deleteChatMessage(messageId, chatClient.userId, chatClient.isAdmin);
              }

              broadcastToChatClients('messages_deleted', {
                messageIds: data.messageIds
              });

            } catch (error) {
              console.error('Error deleting selected messages:', error);
              ws.send(JSON.stringify({
                type: 'error',
                message: 'Failed to delete selected messages'
              }));
            }
          }
        }
        else if (data.type === 'ban_user') {
          const chatClient = chatClients.get(clientId);
          if (chatClient && chatClient.isAdmin) {
            try {
              // Add user to banned users list
              const bannedUser = {
                userId: data.userId,
                username: data.username,
                bannedBy: chatClient.userId,
                bannedAt: new Date(),
                reason: data.reason || 'Chat violations'
              };

              // Note: banUser functionality should be implemented in storage if needed
              // await storage.banUser(bannedUser);

              broadcastToChatClients('user_banned', {
                userId: data.userId,
                bannedBy: chatClient.userId,
                reason: data.reason
              });

            } catch (error) {
              console.error('Error banning user:', error);
              ws.send(JSON.stringify({
                type: 'error',
                message: 'Failed to ban user'
              }));
            }
          }
        }
      } catch (error) {
        console.error('WebSocket message error:', error);
      }
    });

    ws.on('close', () => {
      wsConnections.delete(clientId);
      const chatClient = chatClients.get(clientId);
      if (chatClient) {
        chatClients.delete(clientId);
        // Broadcast user left to other clients
        broadcastToChatClients('user_left', {
          userId: chatClient.userId
        }, clientId);
      }
      console.log(`WebSocket client disconnected: ${clientId}`);
    });

    ws.on('error', (error) => {
      console.error('WebSocket error:', error);
      wsConnections.delete(clientId);
      chatClients.delete(clientId);
    });
  });

  // Chat API routes for message management
  app.patch('/api/chat/messages/:id', isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const { content } = req.body;
      const userId = req.user._id.toString();

      if (!content || content.trim().length === 0) {
        return res.status(400).json({ message: 'Message content is required' });
      }

      await storage.updateChatMessage(id, content.trim(), userId);
      res.json({ message: 'Message updated successfully' });
    } catch (error) {
      console.error('Error updating chat message:', error);
      res.status(500).json({ message: error instanceof Error ? error.message : 'Failed to update message' });
    }
  });

  app.delete('/api/chat/messages/:id', isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const userId = req.user._id.toString();
      const isAdmin = !!req.user.isAdmin;

      await storage.deleteChatMessage(id, userId, isAdmin);
      res.json({ message: 'Message deleted successfully' });
    } catch (error) {
      console.error('Error deleting chat message:', error);
      res.status(500).json({ message: error instanceof Error ? error.message : 'Failed to delete message' });
    }
  });

  app.get('/api/chat/messages/:id', isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const message = await storage.getChatMessage(id);

      if (!message) {
        return res.status(404).json({ message: 'Message not found' });
      }

      res.json(message);
    } catch (error) {
      console.error('Error fetching chat message:', error);
      res.status(500).json({ message: 'Failed to fetch message' });
    }
  });

  // User settings API routes
  app.get('/api/user/profile', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      // Return user profile with preferences
      res.json({
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        username: user.username,
        bio: user.bio,
        isAdmin: user.isAdmin,
        role: user.role,
        status: user.status,
        coinBalance: user.coinBalance,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin,
        preferences: user.preferences || {
          emailNotifications: true,
          darkMode: false,
          language: 'en',
          timezone: 'UTC'
        }
      });
    } catch (error) {
      console.error('Error fetching user profile:', error);
      res.status(500).json({ message: 'Failed to fetch profile' });
    }
  });

  app.put('/api/user/profile', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const { firstName, lastName, username, bio } = req.body;

      if (!firstName?.trim()) {
        return res.status(400).json({ message: 'First name is required' });
      }

      // Check if username is already taken by another user
      if (username) {
        const existingUser = await storage.getUserByUsername(username);
        if (existingUser && existingUser._id.toString() !== userId) {
          return res.status(400).json({ message: 'Username already taken' });
        }
      }

      await storage.updateUserProfile(userId, {
        firstName: firstName.trim(),
        lastName: lastName?.trim() || '',
        username: username?.trim() || '',
        bio: bio?.trim() || ''
      });

      res.json({ message: 'Profile updated successfully' });
    } catch (error) {
      console.error('Error updating user profile:', error);
      res.status(500).json({ message: 'Failed to update profile' });
    }
  });

  app.put('/api/user/preferences', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const preferences = req.body;

      await storage.updateUserPreferences(userId, preferences);
      res.json({ message: 'Preferences updated successfully' });
    } catch (error) {
      console.error('Error updating user preferences:', error);
      res.status(500).json({ message: 'Failed to update preferences' });
    }
  });

  // Deployment logs API routes
  app.post('/api/deployments/:id/logs', isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const { logs } = req.body;

      if (!Array.isArray(logs)) {
        return res.status(400).json({ message: 'Logs must be an array' });
      }

      await storage.addDeploymentLogs(id, logs);

      // Analyze logs to determine deployment status
      const analysis = await storage.analyzeDeploymentStatus(id);
      if (analysis.status !== 'deploying') {
        await storage.updateDeploymentStatus(id, analysis.status);
      }

      res.json({ message: 'Logs added successfully', analysis });
    } catch (error) {
      console.error('Error adding deployment logs:', error);
      res.status(500).json({ message: 'Failed to add logs' });
    }
  });

  app.get('/api/deployments/:id/status', isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const analysis = await storage.analyzeDeploymentStatus(id);
      res.json(analysis);
    } catch (error) {
      console.error('Error analyzing deployment status:', error);
      res.status(500).json({ message: 'Failed to analyze status' });
    }
  });

  // Coin transfer routes
  app.post('/api/coins/transfer', isAuthenticated, async (req: any, res) => {
    try {
      const senderId = req.user._id.toString();
      const { toEmailOrUsername, amount, message } = req.body;

      if (!toEmailOrUsername || !amount || amount <= 0) {
        return res.status(400).json({ message: 'Valid recipient and positive amount required' });
      }

      // Find recipient
      const recipient = await storage.getUserByUsernameOrEmail(toEmailOrUsername);
      if (!recipient) {
        return res.status(404).json({ message: 'Recipient not found' });
      }

      // Check if trying to send to self
      if (senderId === recipient._id.toString()) {
        return res.status(400).json({ message: 'Cannot send coins to yourself' });
      }

      const sender = await storage.getUser(senderId);
      if (!sender) {
        return res.status(404).json({ message: 'Sender not found' });
      }

      // Check balance
      if (sender.coinBalance < amount) {
        return res.status(400).json({ message: 'Insufficient balance' });
      }

      // Create transfer
      const transfer = await storage.createCoinTransfer({
        fromUserId: senderId,
        toUserId: recipient._id.toString(),
        fromEmail: sender.email,
        toEmailOrUsername,
        amount,
        message: message || '',
        status: 'pending'
      });

      // Process transfer immediately
      await storage.processCoinTransfer(transfer._id.toString());

      res.json({
        message: 'Coins transferred successfully',
        amount,
        recipient: toEmailOrUsername,
        transferId: transfer._id
      });
    } catch (error) {
      console.error('Error transferring coins:', error);
      res.status(500).json({ message: (error as Error).message || 'Failed to transfer coins' });
    }
  });

  // Get user's coin transfers
  app.get('/api/coins/transfers', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user._id.toString();
      const transfers = await storage.getCoinTransfers(userId);
      res.json(transfers);
    } catch (error) {
      console.error('Error fetching transfers:', error);
      res.status(500).json({ message: 'Failed to fetch transfers' });
    }
  });

  // Admin: Get all deployments with numbers
  app.get('/api/admin/deployments/all', requireAdmin, async (req, res) => {
    try {
      const deployments = await storage.getAllDeployments();

      // Add deployment numbers for each user
      const deploymentsWithNumbers = await Promise.all(
        deployments.map(async (deployment) => {
          const totalDeployments = await storage.getUserTotalDeployments(deployment.userId.toString());
          const deploymentNumber = await storage.getNextDeploymentNumber(deployment.userId.toString()) - 1;

          return {
            ...deployment,
            deploymentNumber,
            totalDeployments
          };
        })
      );

      res.json(deploymentsWithNumbers);
    } catch (error) {
      console.error('Error fetching all deployments:', error);
      res.status(500).json({ message: 'Failed to fetch deployments' });
    }
  });

  // Admin: Get users with country information
  app.get('/api/admin/users/countries', requireAdmin, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 100;
      const search = req.query.search as string;

      let users = await storage.getAllUsersWithCountryInfo(limit);

      // Apply search filter if provided
      if (search) {
        users = users.filter(user => 
          user.email.toLowerCase().includes(search.toLowerCase()) ||
          user.firstName?.toLowerCase().includes(search.toLowerCase()) ||
          user.lastName?.toLowerCase().includes(search.toLowerCase()) ||
          user.username?.toLowerCase().includes(search.toLowerCase()) ||
          user.country?.toLowerCase().includes(search.toLowerCase())
        );
      }

      // Auto-detect country for users without country info
      const usersWithCountry = await Promise.all(
        users.map(async (user) => {
          if (!user.country && (user.registrationIp || user.lastLoginIp)) {
            const ip = user.lastLoginIp || user.registrationIp;
            try {
              // Use IP-API.com for country detection (free, no API key needed)
              const response = await fetch(`http://ip-api.com/json/${ip}?fields=country,countryCode`);
              if (response.ok) {
                const geoData = await response.json();
                if (geoData.country) {
                  await storage.updateUserCountry(user._id.toString(), geoData.country);
                  return { ...user, country: geoData.country };
                }
              }
            } catch (error) {
              console.error(`Failed to get country for IP ${ip}:`, error);
            }
          }
          return user;
        })
      );

      res.json(usersWithCountry);
    } catch (error) {
      console.error('Error fetching users with countries:', error);
      res.status(500).json({ message: 'Failed to fetch user countries' });
    }
  });

  // Admin: Banned users list
  app.get('/api/admin/banned-users', requireAdmin, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 100;
      const bannedUsers = await storage.getBannedUsers(limit);
      res.json(bannedUsers);
    } catch (error) {
      console.error('Error fetching banned users:', error);
      res.status(500).json({ message: 'Failed to fetch banned users' });
    }
  });

  // Admin: Add user to banned list
  app.post('/api/admin/banned-users', requireAdmin, async (req: any, res) => {
    try {
      const { userId, reason } = req.body;
      const adminId = req.user._id.toString();

      if (!userId || !reason) {
        return res.status(400).json({ message: 'User ID and reason are required' });
      }

      // Get user info
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      // Create banned user record
      const bannedUser = await storage.createBannedUser({
        userId,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        reason,
        bannedBy: adminId,
        country: user.country,
        deviceFingerprints: user.deviceHistory || [],
        isActive: true
      });

      // Update user status to banned
      await storage.updateUserStatus(userId, 'banned', ['account_banned']);

      res.json({
        message: 'User added to banned list successfully',
        bannedUser
      });
    } catch (error) {
      console.error('Error adding user to banned list:', error);
      res.status(500).json({ message: 'Failed to ban user' });
    }
  });

  // Admin: Remove user from banned list
  app.delete('/api/admin/banned-users/:userId', requireAdmin, async (req, res) => {
    try {
      const { userId } = req.params;

      await storage.removeBannedUser(userId);
      await storage.updateUserStatus(userId, 'active', []);

      res.json({ message: 'User removed from banned list successfully' });
    } catch (error) {
      console.error('Error removing user from banned list:', error);
      res.status(500).json({ message: 'Failed to unban user' });
    }
  });

  // Voucher Management Routes

  // Admin: Create voucher code
  app.post('/api/admin/vouchers', requireAdmin, async (req: any, res) => {
    try {
      const { code, coinAmount, maxUsage, expiresAt } = req.body;

      // Check if voucher code already exists
      const existingVoucher = await storage.getVoucherByCode(code);
      if (existingVoucher) {
        return res.status(400).json({ message: 'Voucher code already exists' });
      }

      // Prepare voucher data with proper types
      const voucherData = {
        code: code?.toUpperCase() || '',
        coinAmount: parseInt(coinAmount) || 0,
        createdBy: (req.user._id || req.user.id).toString(),
        maxUsage: parseInt(maxUsage) || 1,
        isActive: true,
        ...(expiresAt && { expiresAt: new Date(expiresAt) })
      };

      // Validate the data
      const validatedData = insertVoucherCodeSchema.parse(voucherData);

      const voucher = await storage.createVoucherCode(validatedData);

      res.json({ message: 'Voucher created successfully', voucher });
    } catch (error) {
      console.error('Error creating voucher:', error);
      if (error && typeof error === 'object' && 'issues' in error) {
        // Zod validation error
        return res.status(400).json({ 
          message: 'Validation failed',
          errors: (error as any).issues.map((i: any) => `${i.path.join('.')}: ${i.message}`)
        });
      }
      res.status(500).json({ message: 'Failed to create voucher' });
    }
  });

  // Admin: Get all vouchers
  app.get('/api/admin/vouchers', requireAdmin, async (req, res) => {
    try {
      const vouchers = await storage.getAllVouchers();
      res.json(vouchers);
    } catch (error) {
      console.error('Error fetching vouchers:', error);
      res.status(500).json({ message: 'Failed to fetch vouchers' });
    }
  });

  // Admin: Update voucher status
  app.patch('/api/admin/vouchers/:id/status', requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const { isActive } = req.body;

      await storage.updateVoucherStatus(id, isActive);
      res.json({ message: 'Voucher status updated successfully' });
    } catch (error) {
      console.error('Error updating voucher status:', error);
      res.status(500).json({ message: 'Failed to update voucher status' });
    }
  });

  // Admin: Delete voucher
  app.delete('/api/admin/vouchers/:id', requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      await storage.deleteVoucher(id);
      res.json({ message: 'Voucher deleted successfully' });
    } catch (error) {
      console.error('Error deleting voucher:', error);
      res.status(500).json({ message: 'Failed to delete voucher' });
    }
  });

  // User: Redeem voucher code
  app.post('/api/vouchers/redeem', isAuthenticated, async (req: any, res) => {
    try {
      const { code } = req.body;

      if (!code || typeof code !== 'string') {
        return res.status(400).json({ message: 'Voucher code is required' });
      }

      const result = await storage.redeemVoucher(code.trim().toUpperCase(), req.user._id.toString());

      if (result.success) {
        res.json(result);
      } else {
        res.status(400).json(result);
      }
    } catch (error) {
      console.error('Error redeeming voucher:', error);
      res.status(500).json({ message: 'Failed to redeem voucher' });
    }
  });

  // Database Usage Statistics
  app.get('/api/admin/database/stats', requireAdmin, async (req, res) => {
    try {
      const stats = await storage.getDatabaseStats();
      res.json(stats);
    } catch (error) {
      console.error('Error fetching database stats:', error);
      res.status(500).json({ message: 'Failed to fetch database statistics' });
    }
  });

  app.post('/api/admin/database/cleanup', requireAdmin, async (req, res) => {
    try {
      const result = await storage.performDatabaseCleanup();
      res.json(result);
    } catch (error) {
      console.error('Error performing database cleanup:', error);
      res.status(500).json({ message: 'Failed to perform database cleanup' });
    }
  });

  // Auto-check deployment status periodically - Fixed workflow rerun
  let deploymentCheckInterval: NodeJS.Timeout | null = null;

  const startDeploymentMonitoring = () => {
    if (deploymentCheckInterval) {
      clearInterval(deploymentCheckInterval);
    }

    deploymentCheckInterval = setInterval(async () => {
      try {
        const deployments = await storage.getDeployments();
        const deployingDeployments = deployments.filter(d => d.status === 'deploying');

        for (const deployment of deployingDeployments) {
          const analysis = await storage.analyzeDeploymentStatus(deployment._id.toString());
          if (analysis.status !== 'deploying') {
            await storage.updateDeploymentStatus(deployment._id.toString(), analysis.status);
            console.log(`Updated deployment ${deployment._id} status to: ${analysis.status}`);
          }
        }
      } catch (error) {
        console.error('Error in deployment status check:', error);
      }
    }, 2 * 60 * 1000); // Check every 2 minutes
  };

  // Start deployment monitoring
  startDeploymentMonitoring();

  return httpServer;
}

// Export storage for use in other modules
export { storage };
