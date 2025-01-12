/**
 * Copyright 2022-2024 HEIG-VD
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import NextAuth from 'next-auth';
import KeycloakProvider from 'next-auth/providers/keycloak';
import { PrismaAdapter } from '@next-auth/prisma-adapter';
import { Role } from '@prisma/client';
import { getPrisma } from '@/middleware/withPrisma';

const prisma = getPrisma();

const prismaAdapter = PrismaAdapter(prisma);

const MyAdapter = {
  ...prismaAdapter,
  linkAccount: (account) => {
    account['not_before_policy'] = account['not-before-policy'];
    delete account['not-before-policy'];
    return prismaAdapter.linkAccount(account);
  },
};

const switchEduId = {
  id: 'switch',
  name: 'SWITCH edu-ID',
  type: 'oauth',
  wellKnown: 'https://login.eduid.ch/.well-known/openid-configuration', 
  clientId: process.env.NEXTAUTH_SWITCH_CLIENT_ID,  
  clientSecret: process.env.NEXTAUTH_SWITCH_CLIENT_SECRET, 
  authorization: {
    params: {
      scope: 'openid profile email https://login.eduid.ch/authz/User.Read',
      claims: JSON.stringify({
        id_token: {
          name: { essential: true },
          email: { essential: true },
          swissEduIDLinkedAffiliation: { essential: true },
          swissEduIDAssociatedMail: { essential: true },
          swissEduIDLinkedAffiliationMail: { essential: true },
          swissEduID: { essential: true },
          eduPersonEntitlement: { essential: true },
          eduPersonAffiliation: { essential: true },
        },
      }),
    },
  },
  idToken: true,
  checks: ['pkce', 'state'],
  profile(OAuthProfile) {
    return {
      id: OAuthProfile.sub,
      name: OAuthProfile.name,
      email: OAuthProfile.email,
      roles: [Role.STUDENT],
      affiliations: OAuthProfile.swissEduIDLinkedAffiliationMail,
      organizations: OAuthProfile.swissEduIDLinkedAffiliationMail.map((affiliation) => affiliation.split('@')[1]),
      selectedAffiliation: null,
    };
  },
};

export const authOptions = {
  adapter: MyAdapter,
  providers: [
    KeycloakProvider({
      clientId: process.env.NEXTAUTH_KEYCLOAK_CLIENT_ID,
      clientSecret: process.env.NEXTAUTH_KEYCLOAK_CLIENT_SECRET,
      issuer: process.env.NEXTAUTH_KEYCLOAK_ISSUER_BASE_URL,
    }),
    switchEduId,
  ],
  secret: process.env.NEXTAUTH_SECRET,
  callbacks: {
    async session({ session, user }) {
      if (user) {
        const userWithGroups = await prisma.user.findUnique({
          where: { email: user.email },
          include: {
            groups: {
              include: {
                group: true,
              },
              orderBy: {
                group: {
                  label: 'asc',
                },
              },
            },
          },
        });

        if (userWithGroups) {
          session.user.groups = userWithGroups.groups.map((g) => g.group.scope);
          session.user.selected_group = userWithGroups.groups.find(
            (g) => g.selected
          )?.group.scope;
        }
      }
      session.user.id = user.id;
      session.user.roles = user.roles;
      return session;
    },

    async signIn({ user, account, profile }) {
      if (!user.email) {
        return false;
      }

      const accountData = {
        type: account.type,
        provider: account.provider,
        providerAccountId: account.providerAccountId,
        refresh_token: account.refresh_token,
        access_token: account.access_token,
        expires_at: account.expires_at,
        refresh_expires_in: account.refresh_expires_in,
        not_before_policy: account['not-before-policy'],
        token_type: account.token_type,
        scope: account.scope,
        id_token: account.id_token,
        session_state: account.session_state,
      };

      const existingUser = await prisma.user.findUnique({
        where: { email: user.email },
      });

      if (!existingUser) {
        // Create a new user
        await prisma.user.create({
          data: {
            email: user.email,
            name: profile.name,
            roles: [Role.STUDENT],
            affiliations: [account.provider === 'switch' ? profile.swissEduIDLinkedAffiliationMail : user.email],
            organizations: [account.provider === 'switch' ? profile.swissEduIDLinkedAffiliationMail.map((affiliation) => affiliation.split('@')[1]) : user.email.split('@')[1]],
          },
        });

        // Link the account
        await prisma.account.create({
          data: {
            userId: existingUser.id,
            ...accountData,
          },
        });
        return true;
      }

      // If the user exists, check if the account is already linked
      const linkedAccount = await prisma.account.findFirst({
        where: {
          providerAccountId: account.providerAccountId,
          provider: account.provider,
        },
      });

      if (!linkedAccount) {
        // Update the user name with trustworthy name from Keycloak or SWITCH edu-ID
        await prisma.user.update({
          where: { email: user.email },
          data: {
            name: profile.name,
          },
        });

        // Link the account
        await prisma.account.create({
          data: {
            userId: existingUser.id,
            ...accountData,
          },
        });
      }

      return true;
    },
  },
};

export default NextAuth(authOptions);
