import { Role } from '@prisma/client'
import { getUser } from '../../../../../code/auth'
import { withAuthorization, withMethodHandler } from '../../../../../middleware/withAuthorization'
import { withPrisma } from '../../../../../middleware/withPrisma'

/** Managing the members of a group
 *
 * get: list members of a group
 * post: add a member to a group
 * del: remove a member from a group
*/

const get = async (req, res, prisma) => {
  // get all members of group
  const { groupId } = req.query

  // check if the users is a member of the group they are trying to get members of
  const user = await getUser(req)

  if (!user) {
    res.status(401).json({ message: 'Unauthorized' })
    return
  }

  const userIsMemberOfGroup = await prisma.group.findFirst({
    where: {
      id: groupId,
      members: {
        some: {
          userId: user.id,
        },
      },
    },
  })

  if (!userIsMemberOfGroup) {
    res.status(401).json({ message: 'Unauthorized' })
    return
  }

  const members = await prisma.group.findUnique({
    where: {
      id: groupId,
    },
    include: {
      members: {
        include: {
          user: true,
        },
      },
    },
  })

  res.status(200).json(members)
}

const post = async (req, res, prisma) => {
  // add member to group
  const { groupId } = req.query
  const { member } = req.body

  // check if the users is a member of the group they are trying to add a member to
  const requester = await getUser(req)

  if (!requester) {
    res.status(401).json({ message: 'Unauthorized' })
    return
  }

  const requesterIsMemberOfGroup = await prisma.group.findFirst({
    where: {
      id: groupId,
      members: {
        some: {
          userId: requester.id,
        },
      },
    },
  })

  if (!requesterIsMemberOfGroup) {
    res.status(401).json({ message: 'Unauthorized' })
    return
  }

  try {
    const membership = await prisma.userOnGroup.create({
      data: {
        userId: member.id,
        groupId,
      },
      select: {
        user: true,
      },
    })

    res.status(200).json(membership)
  } catch (e) {
    switch (e.code) {
      case 'P2002':
        res.status(409).json({ message: 'Member already exists' })
        break
      default:
        res.status(500).json({ message: 'Internal server error' })
    }
  }
}

const del = async (req, res, prisma) => {
  // remove member from group
  const { groupId } = req.query

  const user = await getUser(req)

  // check if the users is a member of the group they are trying to remove a member from
  const userIsMemberOfGroup = await prisma.group.findFirst({
    where: {
      id: groupId,
      members: {
        some: {
          userId: user.id,
        },
      },
    },
  })

  if (!userIsMemberOfGroup) {
    res.status(401).json({ message: 'Unauthorized' })
    return
  }

  await prisma.userOnGroup.delete({
    where: {
      userId_groupId: {
        userId: user.id,
        groupId,
      },
    },
  })

  res.status(200).json({ message: 'Member removed' })
}


export default withMethodHandler({
  GET: withAuthorization(
    withPrisma(get), [Role.PROFESSOR]
  ),
  POST: withAuthorization(
    withPrisma(post), [Role.PROFESSOR]
  ),
  DELETE: withAuthorization(
    withPrisma(del), [Role.PROFESSOR]
  ),
})
