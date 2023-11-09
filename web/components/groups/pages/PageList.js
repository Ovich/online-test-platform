import { useState, useEffect, useCallback } from 'react'
import useSWR from 'swr'
import LayoutMain from '../../layout/LayoutMain'
import { Box, Button, Stack, Typography } from '@mui/material'

import { Role } from '@prisma/client'
import Authorisation from '../../security/Authorisation'
import AlertFeedback from '../../feedback/AlertFeedback'
import Link from 'next/link'
import ArrowBackIosIcon from '@mui/icons-material/ArrowBackIos'
import LayoutSplitScreen from '../../layout/LayoutSplitScreen'

import AddGroupDialog from '../list/AddGroupDialog'
import AddMemberDialog from '../list/AddMemberDialog'
import MyGroupsGrid from '../list/MyGroupsGrid'
import GroupMembersGrid from '../list/GroupMembersGrid'
import Loading from '../../feedback/Loading'
import { fetcher } from '../../../code/utils'
import {useGroup} from "../../../context/GroupContext";

const PageList = () => {

  const { groups } = useGroup()

  const [selectedGroup, setSelectedGroup] = useState()

  const [addGroupDialogOpen, setAddGroupDialogOpen] = useState(false)
  const [addMemberDialogOpen, setAddMemberDialogOpen] = useState(false)

  const {
    data: group,
    error,
    mutate,
  } = useSWR(
    `/api/groups/${selectedGroup && selectedGroup.id}/members`,
    selectedGroup ? fetcher : null
  )

  useEffect(() => {
    if (groups && groups.length > 0) {
      setSelectedGroup(groups[0].group)
    }
  }, [groups])

  const onGroupsLeaveOrDelete = useCallback(
    async (groupId) => {
      if (selectedGroup && selectedGroup.id === groupId) {
        setSelectedGroup(null)
      }
    },
    [selectedGroup, setSelectedGroup]
  )

  return (
    <Authorisation allowRoles={[Role.PROFESSOR]}>
      <Loading loading={!group} errors={[error]}>
        <LayoutMain
          header={
            <Box>
              <Link href="/">
                <Button startIcon={<ArrowBackIosIcon />}>Back</Button>
              </Link>
            </Box>
          }
        >
          <LayoutSplitScreen
            leftPanel={
              <>
                <Stack
                  direction={'row'}
                  alignItems={'center'}
                  justifyContent={'space-between'}
                  sx={{ p: 1 }}
                >
                  <Typography variant="h6">My Groups</Typography>
                  <Button onClick={() => setAddGroupDialogOpen(true)}>
                    Create a new group
                  </Button>
                </Stack>
                <MyGroupsGrid
                  groups={groups}
                  onSelected={(group) => setSelectedGroup(group)}
                  onLeave={async (groupId) =>
                    await onGroupsLeaveOrDelete(groupId)
                  }
                  onDelete={async (groupId) =>
                    await onGroupsLeaveOrDelete(groupId)
                  }

                />
              </>
            }
            rightPanel={
              group ? (
                <>
                  <Stack
                    direction={'row'}
                    alignItems={'center'}
                    justifyContent={'space-between'}
                    sx={{ p: 1 }}
                  >
                    <Typography variant="h6">
                      Members of {group && group.label}
                    </Typography>
                    <Button onClick={() => setAddMemberDialogOpen(true)}>
                      Add a new member
                    </Button>
                  </Stack>
                  <GroupMembersGrid
                    group={group}
                    onUpdate={
                      async () => {
                        await mutate()
                        await mutateGroups()
                      }

                    }
                  />
                </>
              ) : (
                <Stack p={2}>
                  <AlertFeedback severity="info">
                    <Typography variant="body1">
                      Select a group on the left to view its members.
                    </Typography>
                  </AlertFeedback>
                </Stack>
              )
            }
          />

          <AddGroupDialog
            open={addGroupDialogOpen}
            onClose={() => setAddGroupDialogOpen(false)}
          />

          <AddMemberDialog
            group={group}
            open={addMemberDialogOpen}
            onClose={() => setAddMemberDialogOpen(false)}
            onSuccess={async () => await mutate()} // force refresh
          />
        </LayoutMain>
      </Loading>
    </Authorisation>
  )
}

export default PageList
