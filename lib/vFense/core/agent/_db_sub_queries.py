from vFense.db.client import r
from vFense.core.tag import TagCollections, TagsPerAgentKeys, \
    TagsPerAgentIndexes, TagsKeys

class Merge():
    TAGS = (
        {
            TagCollections.Tags: (
                r
                .table(TagCollections.TagsPerAgent)
                .get_all(
                    r.row[TagsPerAgentKeys.AgentId],
                    index=TagsPerAgentIndexes.AgentId
                )
                .eq_join(
                    TagsKeys.TagId,
                    r.table(TagCollections.Tags)
                )
                .zip()
                .pluck(
                    TagsPerAgentKeys.TagId,
                    TagsPerAgentKeys.TagName
                )
                .coerce_to('array')
            )
        }
    )

