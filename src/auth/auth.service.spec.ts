import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { SupabaseService } from '../supabase/supabase.service';
import { UnauthorizedException, BadRequestException } from '@nestjs/common';

describe('AuthService', () => {
  let service: AuthService;
  let supabaseService: SupabaseService;

  const mockSupabaseService = {
    getAdminClient: jest.fn(() => ({
      auth: {
        signUp: jest.fn(),
        signInWithPassword: jest.fn(),
        signInWithOAuth: jest.fn(),
        admin: {
          signOut: jest.fn(),
        },
      },
    })),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: SupabaseService,
          useValue: mockSupabaseService,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    supabaseService = module.get<SupabaseService>(SupabaseService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('register', () => {
    it('should successfully register a user', async () => {
      const registerDto = {
        email: 'test@example.com',
        password: 'password123',
      };

      const mockResponse = {
        data: { user: { id: '1', email: 'test@example.com' } },
        error: null,
      };

      jest.spyOn(supabaseService.getAdminClient().auth, 'signUp')
        .mockResolvedValue(mockResponse as any);

      const result = await service.register(registerDto);

      expect(result.message).toBe('Registration successful');
      expect(result.user).toEqual(mockResponse.data.user);
    });

    it('should throw BadRequestException on registration error', async () => {
      const registerDto = {
        email: 'test@example.com',
        password: 'password123',
      };

      const mockError = {
        data: { user: null },
        error: { message: 'Registration failed' },
      };

      jest.spyOn(supabaseService.getAdminClient().auth, 'signUp')
        .mockResolvedValue(mockError as any);

      await expect(service.register(registerDto))
        .rejects.toThrow(BadRequestException);
    });
  });

  describe('login', () => {
    it('should successfully login a user', async () => {
      const loginDto = {
        email: 'test@example.com',
        password: 'password123',
      };

      const mockResponse = {
        data: {
          session: { access_token: 'token' },
          user: { id: '1', email: 'test@example.com' },
        },
        error: null,
      };

      jest.spyOn(supabaseService.getAdminClient().auth, 'signInWithPassword')
        .mockResolvedValue(mockResponse as any);

      const result = await service.login(loginDto);

      expect(result.message).toBe('Login successful');
      expect(result.session).toEqual(mockResponse.data.session);
      expect(result.user).toEqual(mockResponse.data.user);
    });

    it('should throw UnauthorizedException on login error', async () => {
      const loginDto = {
        email: 'test@example.com',
        password: 'wrong-password',
      };

      const mockError = {
        data: { session: null, user: null },
        error: { message: 'Invalid credentials' },
      };

      jest.spyOn(supabaseService.getAdminClient().auth, 'signInWithPassword')
        .mockResolvedValue(mockError as any);

      await expect(service.login(loginDto))
        .rejects.toThrow(UnauthorizedException);
    });
  });
});